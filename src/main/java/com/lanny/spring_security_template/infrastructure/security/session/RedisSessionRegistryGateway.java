package com.lanny.spring_security_template.infrastructure.security.session;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;

/**
 * ============================================================
 * RedisSessionRegistryGateway
 * ============================================================
 *
 * <p>
 * Redis-backed implementation of {@link SessionRegistryGateway} used in
 * production environments to track active user sessions.
 * </p>
 *
 * <h2>Data model</h2>
 * <p>
 * Sessions are stored in a Redis ZSET where:
 * </p>
 * <ul>
 * <li><b>Key</b>: {@code security:sessions:v1:{username}}</li>
 * <li><b>Member</b>: JWT identifier (jti)</li>
 * <li><b>Score</b>: expiration timestamp (epoch seconds)</li>
 * </ul>
 *
 * <h2>Expiration strategy</h2>
 * <p>
 * Expired sessions are removed using a <b>lazy cleanup strategy</b>
 * before read and count operations.
 * </p>
 *
 * <h2>Concurrency guarantees</h2>
 * <ul>
 * <li>Redis ZSET operations are atomic</li>
 * <li>No background schedulers are required</li>
 * <li>Expired sessions are never returned</li>
 * </ul>
 *
 * <p>
 * Enabled only in {@code prod} and {@code demo} profiles.
 * </p>
 */
@Component
@Profile({ "prod", "demo" })
public class RedisSessionRegistryGateway implements SessionRegistryGateway {

    private static final String KEY_PREFIX = "security:sessions:v1:";

    private final RedisTemplate<String, String> redis;

    public RedisSessionRegistryGateway(RedisTemplate<String, String> redis) {
        this.redis = redis;
    }

    private @NonNull String key(@NonNull String username) {
        return KEY_PREFIX + username;
    }

    @Override
    @SuppressWarnings("null") // RedisTemplate returns nullable types
    public void registerSession(String username, String jti, Instant expiresAt) {
        redis.opsForZSet()
                .add(key(username), jti, expiresAt.getEpochSecond());
    }

    @Override
    @SuppressWarnings("null")
    public List<String> getActiveSessions(String username) {

        String key = key(username);
        long now = Instant.now().getEpochSecond();

        // Lazy cleanup of expired sessions
        redis.opsForZSet().removeRangeByScore(key, 0, now);

        Set<String> raw = redis.opsForZSet().range(key, 0, -1);

        if (raw == null || raw.isEmpty()) {
            return List.of();
        }

        return raw.stream()
                .filter(Objects::nonNull)
                .toList();
    }

    @Override
    @SuppressWarnings("null")
    public void removeSession(String username, String jti) {
        redis.opsForZSet().remove(key(username), jti);
    }

    @Override
    @SuppressWarnings("null")
    public void removeAllSessions(String username) {
        redis.delete(key(username));
    }

    @Override
    @SuppressWarnings("null")
    public int countSessions(String username) {

        String key = key(username);
        long now = Instant.now().getEpochSecond();

        // Lazy cleanup
        redis.opsForZSet().removeRangeByScore(key, 0, now);

        Long size = redis.opsForZSet().size(key);
        return size == null ? 0 : size.intValue();
    }
}
