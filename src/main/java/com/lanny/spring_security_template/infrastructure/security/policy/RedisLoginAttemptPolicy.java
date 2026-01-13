package com.lanny.spring_security_template.infrastructure.security.policy;

import java.util.List;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;

import lombok.RequiredArgsConstructor;

/**
 * ============================================================
 * RedisLoginAttemptPolicy
 * ============================================================
 *
 * <p>
 * Redis-backed implementation of {@link LoginAttemptPolicy} providing
 * distributed, atomic rate limiting for authentication endpoints.
 * </p>
 *
 * <h2>Execution guarantees</h2>
 * <ul>
 * <li>Atomic enforcement via Lua script</li>
 * <li>Consistent behavior across multiple application instances</li>
 * <li>No partial state updates</li>
 * <li>Never returns {@code null}</li>
 * </ul>
 *
 * <h2>Failure model</h2>
 * <ul>
 * <li>If Redis is unavailable, the exception propagates</li>
 * <li>Fail-fast behavior is intentional for security consistency</li>
 * <li>No silent bypass of rate limiting in production</li>
 * </ul>
 *
 * <h2>Security constraints</h2>
 * <ul>
 * <li>Rate-limit keys must be PII-safe (hashed upstream)</li>
 * <li>TTL values returned reflect real Redis state</li>
 * <li>No assumptions about request content</li>
 * </ul>
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
         * <ul>
         * <li>{@code 0} → access allowed</li>
         * <li>{@code >0} → blocked, value represents remaining block TTL (seconds)</li>
         * </ul>
         *
         * <p>
         * Script invariants:
         * </p>
         * <ul>
         * <li>Attempts counter always has a TTL</li>
         * <li>Block key is always created with TTL</li>
         * <li>No negative TTLs are propagated</li>
         * </ul>
         */
        @NonNull
        private final RedisScript<Long> script = new DefaultRedisScript<>(
                        """
                                        local attemptsKey = KEYS[1]
                                        local blockKey = KEYS[2]

                                        local maxAttempts = tonumber(ARGV[1])
                                        local windowSeconds = tonumber(ARGV[2])
                                        local blockSeconds = tonumber(ARGV[3])

                                        local blockTtl = redis.call("TTL", blockKey)

                                        -- Active block → return remaining TTL
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

        @SuppressWarnings("null")
        @Override
        public LoginAttemptResult registerAttempt(String key) {

                List<String> keys = List.of(
                                ATTEMPTS_PREFIX + key,
                                BLOCK_PREFIX + key);

                Long result = redis.execute(
                                script,
                                keys,
                                String.valueOf(props.maxAttempts()),
                                String.valueOf(props.window()),
                                String.valueOf(props.blockSeconds()));

                long retryAfter = (result != null && result > 0) ? result : 0;

                if (retryAfter > 0) {
                        metrics.recordBruteForceDetected();
                        return LoginAttemptResult.blocked(retryAfter);
                }

                return LoginAttemptResult.allowAccess();
        }

        @SuppressWarnings("null")
        @Override
        public void resetAttempts(String key) {
                redis.delete(List.of(
                                ATTEMPTS_PREFIX + key,
                                BLOCK_PREFIX + key));
        }
}
