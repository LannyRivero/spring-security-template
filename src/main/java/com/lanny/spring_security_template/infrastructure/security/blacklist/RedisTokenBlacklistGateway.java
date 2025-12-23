package com.lanny.spring_security_template.infrastructure.security.blacklist;

import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.time.Duration;
import java.util.Objects;

/**
 * Redis-based implementation of {@link TokenBlacklistGateway}.
 *
 * <p>
 * This adapter is responsible for revoking JWTs by storing their {@code jti}
 * (JWT ID) in Redis with a TTL aligned to the token expiration time.
 * </p>
 *
 * <h3>Security guarantees</h3>
 * <ul>
 * <li>Only the {@code jti} is stored — never the full token or sensitive
 * data.</li>
 * <li>Each blacklist entry automatically expires when the JWT becomes
 * invalid.</li>
 * <li>Revocation checks are O(1) using Redis key existence.</li>
 * </ul>
 *
 * <h3>Operational considerations</h3>
 * <ul>
 * <li>This adapter is enabled only in {@code prod} and {@code demo}
 * profiles.</li>
 * <li>Redis TTL ensures no unbounded growth (no manual cleanup required).</li>
 * <li>Clock access is abstracted via {@link ClockProvider} for determinism
 * and consistency across the system.</li>
 * </ul>
 *
 * <p>
 * If the provided expiration time is already in the past (or results in a
 * non-positive TTL), the revocation operation is ignored, as the token is
 * already expired and does not require blacklisting.
 * </p>
 */

@Component
@Profile({ "prod", "demo" })
@RequiredArgsConstructor
public class RedisTokenBlacklistGateway implements TokenBlacklistGateway {

    private final StringRedisTemplate redis;
    private static final String PREFIX = "blacklist:jti:";
    private final ClockProvider clock;

    /**
     * Revokes a JWT by storing its {@code jti} in Redis with a TTL that matches
     * the token expiration time.
     *
     * @param jti       the unique JWT identifier
     * @param expiresAt the instant at which the token expires
     */
    @Override
    public void revoke(String jti, Instant expiresAt) {
        long ttlSeconds = Duration.between(clock.now(), expiresAt).toSeconds();

        // If the token is already expired or about to expire, no blacklist entry is
        // needed
        if (ttlSeconds <= 0) {
            return;
        }

        redis.opsForValue().set(
                PREFIX + jti,
                "1",
                Objects.requireNonNull(Duration.ofSeconds(ttlSeconds)));
    }

    /**
     * Checks whether a JWT has been revoked.
     *
     * @param jti the unique JWT identifier
     * @return {@code true} if the token has been revoked, {@code false} otherwise
     */
    @Override
    public boolean isRevoked(String jti) {
        return Boolean.TRUE.equals(redis.hasKey(PREFIX + jti));
    }
}