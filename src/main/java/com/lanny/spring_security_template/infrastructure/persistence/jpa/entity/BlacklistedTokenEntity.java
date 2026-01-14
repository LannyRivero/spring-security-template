package com.lanny.spring_security_template.infrastructure.persistence.jpa.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * ============================================================
 * BlacklistedTokenEntity
 * ============================================================
 *
 * <p>
 * Persistence entity representing a revoked JWT access or refresh token.
 * </p>
 *
 * <p>
 * Each record represents an immutable security fact:
 * a token identified by its {@code jti} has been revoked
 * until {@code expiresAt}.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Only the token identifier (JTI) is stored</li>
 * <li>No JWT payload or user data is persisted</li>
 * <li>Entries are naturally bounded by expiration time</li>
 * </ul>
 *
 * <h2>Lifecycle</h2>
 * <ul>
 * <li>Created when a token is revoked</li>
 * <li>Never updated</li>
 * <li>Automatically becomes obsolete after {@code expiresAt}</li>
 * </ul>
 */
@Entity
@Table(name = "blacklisted_tokens", indexes = {
        @Index(name = "idx_blacklisted_token_jti", columnList = "jti")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class BlacklistedTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Unique JWT identifier (JTI).
     *
     * <p>
     * Stored as plain text only because it is already
     * a high-entropy, non-PII identifier.
     * </p>
     */
    @Column(nullable = false, unique = true, updatable = false)
    private String jti;

    /**
     * Expiration timestamp of the revoked token.
     *
     * <p>
     * Used to align blacklist lifetime with token validity.
     * </p>
     */
    @Column(nullable = false, updatable = false)
    private Instant expiresAt;
}
