package com.lanny.spring_security_template.infrastructure.persistence.jpa.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

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
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class RefreshTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String username;

    @Column(name = "jti_hash", nullable = false, length = 64)
    private String jtiHash;

    /**
     * Family ID groups all tokens from the same authentication session.
     * When a token is rotated, the new token inherits the same familyId.
     * Used for reuse detection: if a revoked token in a family is reused,
     * the entire family is revoked.
     */
    @Column(name = "family_id", nullable = false)
    private String familyId;

    /**
     * JTI of the previous token in the rotation chain.
     * Null for the initial token in a family.
     * Forms a linked list: token_B.previousTokenJti = token_A.jti
     */
    @Column(name = "previous_token_jti")
    private String previousTokenJti;

    /**
     * Revocation flag. Set to true when:
     * - Token is rotated (normal flow)
     * - User logs out
     * - Reuse is detected (entire family revoked)
     * - Admin revokes token
     */
    @Column(nullable = false)
    private boolean revoked;

    @Column(nullable = false)
    private Instant issuedAt;

    @Column(nullable = false)
    private Instant expiresAt;
}
