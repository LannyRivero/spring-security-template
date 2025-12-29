package com.lanny.spring_security_template.infrastructure.security.session;

import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Set;

/**
 * RedisSessionRegistryGateway
 *
 * <p>
 * Redis-backed implementation of {@link SessionRegistryGateway}.
 * </p>
 *
 * <p>
 * Active sessions are stored in a Redis ZSET where:
 * </p>
 * <ul>
 * <li><b>member</b> = JWT ID (jti)</li>
 * <li><b>score</b> = expiration timestamp (epoch seconds)</li>
 * </ul>
 *
 * <p>
 * Expired sessions are removed using a <b>lazy cleanup strategy</b>
 * before read operations to guarantee consistency and correctness.
 * </p>
 *
 * <p>
 * This design avoids background schedulers while ensuring that:
 * </p>
 * <ul>
 * <li>Expired sessions are never returned</li>
 * <li>Session counts remain accurate</li>
 * <li>No stale security state leaks</li>
 * </ul>
 *
 * <p>
 * Enabled only in {@code prod} and {@code demo} profiles.
 * </p>
 */
@Component
@Profile({ "prod", "demo" })
public class RedisSessionRegistryGateway implements SessionRegistryGateway {

    private final RedisTemplate<String, String> redis;

    public RedisSessionRegistryGateway(RedisTemplate<String, String> redis) {
        this.redis = redis;
    }

    private @NonNull String key(@NonNull String username) {
        return "sessions:" + username;
    }

    /**
     * Registers a new active session for a user.
     *
     * @param username  authenticated username
     * @param jti       JWT identifier
     * @param expiresAt token expiration instant
     */
    @Override
    @SuppressWarnings("null") // RedisTemplate returns nullable types
    public void registerSession(String username, String jti, Instant expiresAt) {
        redis.opsForZSet()
                .add(key(username), jti, expiresAt.getEpochSecond());
    }

    /**
     * Returns all currently active sessions for a user.
     *
     * <p>
     * Expired sessions are removed before retrieval.
     * </p>
     */
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

    /**
     * Removes a specific session for a user.
     */
    @Override
    @SuppressWarnings("null")
    public void removeSession(String username, String jti) {
        redis.opsForZSet().remove(key(username), jti);
    }

    /**
     * Removes all sessions for a user.
     */
    @Override
    @SuppressWarnings("null")
    public void removeAllSessions(String username) {
        redis.delete(key(username));
    }

    /**
     * Returns the number of active sessions for a user.
     *
     * <p>
     * Performs lazy cleanup before counting to avoid
     * expired session leakage.
     * </p>
     */
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
