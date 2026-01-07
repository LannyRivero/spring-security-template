package com.lanny.spring_security_template.infrastructure.security.policy;

import java.util.List;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * {@code RedisLoginAttemptPolicy}
 *
 * <h2>Purpose</h2>
 * Redis-backed implementation of {@link LoginAttemptPolicy} used to detect and
 * mitigate
 * brute-force attacks against the login endpoint in distributed deployments.
 *
 * <h2>Why Redis</h2>
 * In a multi-instance (multi-pod) architecture, in-memory counters do not
 * provide
 * consistent enforcement. Redis provides a shared, low-latency store suitable
 * for
 * rate-limiting and temporary lockouts.
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li><b>Atomicity</b>: increments, TTL assignment, and lockout creation are
 * executed
 * atomically via a Lua script to prevent race conditions (e.g., INCR without
 * EXPIRE).</li>
 * <li><b>Predictable lockout</b>: lockout TTL returned to callers is the real
 * TTL from Redis,
 * avoiding drift between configuration and actual lock duration.</li>
 * <li><b>PII-safe</b>: this policy does not assume the key contains raw
 * usernames; callers should
 * hash any user identifiers before building the key.</li>
 * </ul>
 *
 * <h2>Algorithm overview</h2>
 * Given a rate-limit key (IP/USER/IP_USER), the policy maintains two Redis
 * keys:
 * <ul>
 * <li>{@code login:attempts:{key}}: counter with TTL = window</li>
 * <li>{@code login:block:{key}}: lockout flag with TTL = blockSeconds</li>
 * </ul>
 *
 * Steps performed atomically:
 * <ol>
 * <li>If block key exists with TTL &gt; 0: return TTL (blocked).</li>
 * <li>INCR attempts counter; if first attempt, set EXPIRE(windowSeconds).</li>
 * <li>If attempts exceeds maxAttempts: SET block key with EX(blockSeconds), DEL
 * attempts key,
 * return blockSeconds (blocked).</li>
 * <li>Otherwise: return 0 (allowed).</li>
 * </ol>
 *
 * <h2>Profiles</h2>
 * Enabled only under {@code prod}. Non-production profiles should use a
 * dedicated
 * no-op or in-memory implementation depending on your threat model for
 * dev/test.
 */
@Component
@Profile("prod")
@RequiredArgsConstructor
public class RedisLoginAttemptPolicy implements LoginAttemptPolicy {

    private static final String ATTEMPTS_PREFIX = "login:attempts:";
    private static final String BLOCK_PREFIX = "login:block:";

    private final StringRedisTemplate redis;
    private final RateLimitingProperties props;
    private final AuthMetricsService metrics;

    /**
     * Lua script that performs the full attempt registration and lockout decision
     * atomically.
     *
     * <p>
     * <b>Return contract</b>
     * </p>
     * <ul>
     * <li>Returns {@code 0} when the attempt is allowed.</li>
     * <li>Returns {@code > 0} with the lockout TTL (in seconds) when blocked.</li>
     * </ul>
     *
     * <p>
     * <b>Keys</b>
     * </p>
     * <ul>
     * <li>KEYS[1] = attemptsKey</li>
     * <li>KEYS[2] = blockKey</li>
     * </ul>
     *
     * <p>
     * <b>Args</b>
     * </p>
     * <ul>
     * <li>ARGV[1] = maxAttempts</li>
     * <li>ARGV[2] = windowSeconds</li>
     * <li>ARGV[3] = blockSeconds</li>
     * </ul>
     */
    private final @NonNull RedisScript<Long> script = new DefaultRedisScript<>(
            """
                    local attemptsKey = KEYS[1]
                    local blockKey = KEYS[2]

                    local maxAttempts = tonumber(ARGV[1])
                    local windowSeconds = tonumber(ARGV[2])
                    local blockSeconds = tonumber(ARGV[3])

                    local blockTtl = redis.call("TTL", blockKey)
                    if blockTtl > 0 then
                      return blockTtl
                    end

                    local attempts = redis.call("INCR", attemptsKey)
                    if attempts == 1 then
                      redis.call("EXPIRE", attemptsKey, windowSeconds)
                    end

                    if attempts > maxAttempts then
                      redis.call("SET", blockKey, "1", "EX", blockSeconds)
                      redis.call("DEL", attemptsKey)
                      return blockSeconds
                    end

                    return 0
                    """,
            Long.class);

    /**
     * Registers an authentication attempt for a given rate-limit key.
     *
     * <p>
     * This method is expected to be called <b>before</b> the authentication flow
     * proceeds,
     * so the login endpoint can be short-circuited when blocked.
     * </p>
     *
     * <p>
     * If blocked, this method returns a {@link LoginAttemptResult} containing a
     * retry-after
     * value based on the real lockout TTL stored in Redis.
     * </p>
     *
     * @param key rate-limiting key (already normalized/hashed by the resolver)
     * @return {@link LoginAttemptResult} indicating whether the attempt should be
     *         blocked
     */
    @Override
    public LoginAttemptResult registerAttempt(String key) {

        final List<String> keys = List.of(
                ATTEMPTS_PREFIX + key,
                BLOCK_PREFIX + key);

        Long retryAfterSeconds = redis.execute(
                script,
                keys,
                String.valueOf(props.maxAttempts()),
                String.valueOf(props.window()),
                String.valueOf(props.blockSeconds()));

        if (retryAfterSeconds != null && retryAfterSeconds > 0) {
            metrics.recordBruteForceDetected();
            return new LoginAttemptResult(true, retryAfterSeconds);
        }

        return new LoginAttemptResult(false, 0);
    }

    /**
     * Resets attempts and block state for the given key.
     *
     * <p>
     * Intended to be called after a successful authentication to clear any previous
     * failed attempts and remove lockout state early.
     * </p>
     *
     * @param key rate-limiting key (same key used in
     *            {@link #registerAttempt(String)})
     */
    @Override
    public void resetAttempts(String key) {
        redis.delete(List.of(
                ATTEMPTS_PREFIX + key,
                BLOCK_PREFIX + key));
    }
}
