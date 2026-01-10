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
         * Lua script return contract:
         * - 0 -> allowed
         * - >0 -> blocked, return TTL seconds
         *
         * Notes:
         * - If blockKey exists but TTL is -1 (no expiry) or -2 (missing), we normalize
         * to 0.
         * - We always set TTL on attemptsKey on first attempt.
         */
        private final @NonNull RedisScript<Long> script = new DefaultRedisScript<>(
                        """
                                        local attemptsKey = KEYS[1]
                                        local blockKey = KEYS[2]

                                        local maxAttempts = tonumber(ARGV[1])
                                        local windowSeconds = tonumber(ARGV[2])
                                        local blockSeconds = tonumber(ARGV[3])

                                        local blockTtl = redis.call("TTL", blockKey)

                                        -- TTL meanings:
                                        -- -2: key does not exist
                                        -- -1: key exists but no expiry (unsafe for lockout keys)
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
                        return LoginAttemptResult.blocked(retryAfterSeconds);
                }

                return LoginAttemptResult.allowAccess();
        }

        @Override
        public void resetAttempts(String key) {
                redis.delete(List.of(
                                ATTEMPTS_PREFIX + key,
                                BLOCK_PREFIX + key));
        }
}