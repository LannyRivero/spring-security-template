package com.lanny.spring_security_template.infrastructure.security.blacklist;

import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

import java.util.Objects;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Redis-based implementation of {@link TokenBlacklistGateway}.
 *
 * <p>
 * This adapter is responsible for revoking JWTs by storing their {@code jti}
 * (JWT ID) in Redis with a TTL aligned to the token expiration time.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Only the {@code jti} is stored — never the full token or sensitive
 * data</li>
 * <li>Each blacklist entry automatically expires when the JWT becomes
 * invalid</li>
 * <li>Revocation checks are O(1) using Redis key existence</li>
 * </ul>
 *
 * <h2>Operational considerations</h2>
 * <ul>
 * <li>Enabled only in {@code prod} and {@code demo} profiles</li>
 * <li>Redis TTL prevents unbounded growth (no cleanup jobs required)</li>
 * <li>Time access is abstracted via {@link ClockProvider} for determinism
 * and testability</li>
 * </ul>
 *
 * <p>
 * If the provided expiration time is already in the past (or results in a
 * non-positive TTL), the revocation operation is safely ignored, as the token
 * is already expired.
 * </p>
 *
 * <p>
 * This implementation is suitable for enterprise and regulated environments
 * (OWASP ASVS, ENS, ISO 27001).
 * </p>
 */
@Component
@Profile({ "prod", "demo" })
@RequiredArgsConstructor
public class RedisTokenBlacklistGateway implements TokenBlacklistGateway {

    /**
     * Prefix used for all blacklist keys stored in Redis.
     *
     * <p>
     * Namespaced to avoid collisions when Redis is shared across services.
     * </p>
     */
    private static final String PREFIX = "security:blacklist:jti:";

    private final StringRedisTemplate redis;
    private final ClockProvider clock;

    /**
     * Revokes a JWT by storing its {@code jti} in Redis with a TTL that matches
     * the token expiration time.
     *
     * <p>
     * The entry is automatically removed by Redis once the TTL expires,
     * ensuring that revoked tokens do not accumulate indefinitely.
     * </p>
     *
     * @param jti       the unique JWT identifier
     * @param expiresAt the instant at which the token expires
     */
    @Override
    public void revoke(String jti, Instant expiresAt) {

        // Defensive guard: invalid identifiers should not be persisted
        if (jti == null || jti.isBlank() || expiresAt == null) {
            return;
        }

        long ttlSeconds = Duration
                .between(clock.now(), expiresAt)
                .toSeconds();

        // Token already expired or about to expire: no blacklist entry required
        if (ttlSeconds <= 0) {
            return;
        }

        redis.opsForValue().set(
                PREFIX + jti,
                "revoked",
                Objects.requireNonNull(Duration.ofSeconds(ttlSeconds)));
    }

    /**
     * Checks whether a JWT has been revoked.
     *
     * <p>
     * This operation performs a constant-time existence check in Redis.
     * </p>
     *
     * @param jti the unique JWT identifier
     * @return {@code true} if the token has been revoked, {@code false} otherwise
     */
    @Override
    public boolean isRevoked(String jti) {

        if (jti == null || jti.isBlank()) {
            return false;
        }

        return Boolean.TRUE.equals(
                redis.hasKey(PREFIX + jti));
    }
}
