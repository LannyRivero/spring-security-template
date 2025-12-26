package com.lanny.spring_security_template.infrastructure.security.policy;

import java.time.Duration;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;

import lombok.RequiredArgsConstructor;

/**
 * Redis-based implementation of {@link LoginAttemptPolicy}.
 *
 * <p>
 * Tracks failed login attempts per username and enforces temporary
 * lockouts after exceeding a configured threshold.
 * </p>
 */
@Component
@RequiredArgsConstructor
@Profile("prod")
public class RedisLoginAttemptPolicy implements LoginAttemptPolicy {

    private static final Logger log = LoggerFactory.getLogger(RedisLoginAttemptPolicy.class);

    private final StringRedisTemplate redis;
    private final RateLimitingProperties props;
    private final AuthMetricsService metrics;

    @Override
    public LoginAttemptResult registerAttempt(String key) {

        String attemptsKey = "login:attempts:" + key;
        String blockKey = "login:block:" + key;

        // Already blocked?
        Long blockTtl = redis.getExpire(blockKey);
        if (blockTtl != null && blockTtl > 0) {
            return new LoginAttemptResult(true, blockTtl);
        }

        // Increment attempts (atomic)
        Long attempts = redis.opsForValue().increment(attemptsKey);

        if (attempts != null && attempts == 1L) {
            redis.expire(attemptsKey, Objects.requireNonNull(Duration.ofSeconds(props.window())));
        }

        if (attempts != null && attempts > props.maxAttempts()) {

            redis.opsForValue().set(blockKey, "1");
            redis.expire(blockKey, Objects.requireNonNull(Duration.ofSeconds(props.blockSeconds())));
            redis.delete(attemptsKey);

            metrics.recordBruteForceDetected();

            log.warn("[AUTH_BRUTEFORCE] login blocked key={}", key);

            return new LoginAttemptResult(true, props.retryAfter());
        }

        return new LoginAttemptResult(false, 0);
    }

    @Override
    public void resetAttempts(String key) {
        redis.delete("login:attempts:" + key);
        redis.delete("login:block:" + key);
    }
}
