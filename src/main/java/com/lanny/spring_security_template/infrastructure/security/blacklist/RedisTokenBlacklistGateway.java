package com.lanny.spring_security_template.infrastructure.security.blacklist;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

import org.springframework.context.annotation.Profile;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

/**
 * ============================================================
 * RedisTokenBlacklistGateway
 * ============================================================
 *
 * <p>
 * Redis-backed implementation of {@link TokenBlacklistGateway} used to revoke
 * JWTs by persisting their {@code jti} with a TTL aligned to token expiration.
 * </p>
 *
 * <h2>Contract</h2>
 * <ul>
 * <li>Best-effort revocation: failures must not break logout flows</li>
 * <li>Only token identifiers ({@code jti}) are stored</li>
 * <li>No full tokens or sensitive data are persisted</li>
 * <li>Automatic cleanup via Redis TTL (no background jobs)</li>
 * </ul>
 *
 * <h2>Operational guarantees</h2>
 * <ul>
 * <li>O(1) revocation checks via Redis key existence</li>
 * <li>Bounded memory usage</li>
 * <li>Deterministic behavior using {@link ClockProvider}</li>
 * </ul>
 *
 * <h2>Failure model</h2>
 * <p>
 * This component is designed to fail safely:
 * <ul>
 * <li>Invalid inputs are ignored</li>
 * <li>Expired tokens are not persisted</li>
 * <li>Exceptions are not propagated to callers</li>
 * </ul>
 * </p>
 */
@Component
@Profile({ "prod", "demo" })
@RequiredArgsConstructor
public class RedisTokenBlacklistGateway implements TokenBlacklistGateway {

    /**
     * Redis key prefix for revoked token identifiers.
     *
     * <p>
     * Format:
     * {@code security:blacklist:jti:{jti}}
     * </p>
     */
    private static final String PREFIX = "security:blacklist:jti:";

    private final StringRedisTemplate redis;
    private final ClockProvider clock;

    @Override
    public void revoke(String jti, Instant expiresAt) {

        if (jti == null || jti.isBlank() || expiresAt == null) {
            return;
        }

        long ttlSeconds = Duration
                .between(clock.now(), expiresAt)
                .toSeconds();

        if (ttlSeconds <= 0) {
            return;
        }

        Duration ttl = Duration.ofSeconds(ttlSeconds);
        redis.opsForValue().set(
                PREFIX + jti,
                "1",
                Objects.requireNonNull(ttl));
    }

    @Override
    public boolean isRevoked(String jti) {

        if (jti == null || jti.isBlank()) {
            return false;
        }

        return Boolean.TRUE.equals(
                redis.hasKey(PREFIX + jti));
    }
}
