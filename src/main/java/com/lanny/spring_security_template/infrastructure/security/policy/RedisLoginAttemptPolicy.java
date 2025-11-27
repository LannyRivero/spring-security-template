package com.lanny.spring_security_template.infrastructure.security.policy;

import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;

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
public class RedisLoginAttemptPolicy implements LoginAttemptPolicy {

    private static final Logger log = LoggerFactory.getLogger(RedisLoginAttemptPolicy.class);

    private final StringRedisTemplate redis;
    private final AuthMetricsService metrics;

    private static final int MAX_ATTEMPTS = 3;
    private static final Duration LOCK_TTL = Duration.ofMinutes(5);

    @SuppressWarnings({ "null" })
    @Override
    public boolean isUserLocked(String username) {
        final var ops = redis.opsForValue();
        final String key = key(username);
        final String value = (String) ops.get(key);

        if (value == null || value.isEmpty())
            return false;

        int attempts = Integer.parseInt(value);
        boolean locked = attempts >= MAX_ATTEMPTS;

        if (locked) {
            log.warn("[AUTH_LOCK] User '{}' temporarily locked ({} failed attempts)", username, attempts);
        }
        return locked;
    }

    @SuppressWarnings({ "null" })
    @Override
    public void recordFailedAttempt(String username) {
        String key = key(username);
        Long attempts = redis.opsForValue().increment(key);

        if (attempts != null && attempts == 1L) {
            redis.expire(key, LOCK_TTL);
        }

        if (attempts != null && attempts >= MAX_ATTEMPTS) {
            metrics.recordBruteForceDetected();
            log.warn("[AUTH_BRUTEFORCE] User '{}' reached {} failed attempts → LOCKED for {} min",
                    username, MAX_ATTEMPTS, LOCK_TTL.toMinutes());
        } else {
            log.info("[AUTH_FAIL] User '{}' failed login ({} / {})", username, attempts, MAX_ATTEMPTS);
        }
    }

    @SuppressWarnings({ "null" })
    @Override
    public void resetAttempts(String username) {
        String keyToDelete = key(username);
        redis.delete(keyToDelete);
        log.debug("[AUTH_RESET] Failed attempts reset for user '{}'", username);
    }

    private String key(String username) {
        return "login:attempts:" + username.toLowerCase();
    }
}
