package com.lanny.spring_security_template.infrastructure.persistence.jpa.entity;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * ============================================================
 * RefreshTokenEntity
 * ============================================================
 *
 * <p>
 * Persistence entity representing a refresh token issued by the
 * authentication system.
 * </p>
 *
 * <p>
 * This entity models a <b>security fact</b>, not a mutable session:
 * once created, a refresh token is immutable except for its
 * revocation status.
 * </p>
 *
 * <h2>Rotation & reuse detection</h2>
 * <ul>
 * <li>Tokens are grouped by {@code familyId}</li>
 * <li>Each rotated token links to its predecessor via
 * {@code previousTokenJti}</li>
 * <li>Reuse of a revoked token triggers family-wide revocation</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Only hashed JTIs are persisted</li>
 * <li>No token material is stored</li>
 * <li>Token lifetime is bounded by {@code expiresAt}</li>
 * </ul>
 */
@Entity
@Table(name = "refresh_tokens", uniqueConstraints = {
                @UniqueConstraint(name = "uk_refresh_token_jti_hash", columnNames = "jti_hash")
}, indexes = {
                @Index(name = "idx_refresh_tokens_family_id", columnList = "family_id"),
                @Index(name = "idx_refresh_tokens_revoked", columnList = "revoked"),
                @Index(name = "idx_refresh_tokens_username_family", columnList = "username, family_id"),
                @Index(name = "idx_refresh_tokens_expires_at", columnList = "expires_at")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class RefreshTokenEntity {

        @Id
        @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;

        /**
         * Username owning this refresh token.
         */
        @Column(nullable = false, updatable = false)
        private String username;

        /**
         * SHA-256 hash of the refresh token JTI.
         */
        @Column(name = "jti_hash", nullable = false, length = 64, updatable = false)
        private String jtiHash;

        /**
         * Identifier grouping all tokens from the same authentication session.
         */
        @Column(name = "family_id", nullable = false, updatable = false)
        private String familyId;

        /**
         * Hashed JTI of the previous token in the rotation chain.
         * Null for the first token in a family.
         */
        @Column(name = "previous_token_jti", updatable = false)
        private String previousTokenJti;

        /**
         * Revocation flag.
         *
         * <p>
         * This is the only mutable field and may change when:
         * <ul>
         * <li>Token is rotated</li>
         * <li>User logs out</li>
         * <li>Reuse is detected</li>
         * <li>Admin revokes the session</li>
         * </ul>
         * </p>
         */
        @Column(nullable = false)
        private boolean revoked;

        @Column(name = "issued_at", nullable = false, updatable = false)
        private Instant issuedAt;

        @Column(name = "expires_at", nullable = false, updatable = false)
        private Instant expiresAt;

        // ------------------------------------------------------------
        // Domain behavior
        // ------------------------------------------------------------

        /**
         * Marks this refresh token as revoked.
         *
         * <p>
         * Idempotent operation.
         * </p>
         */
        public void revoke() {
                this.revoked = true;
        }
}
