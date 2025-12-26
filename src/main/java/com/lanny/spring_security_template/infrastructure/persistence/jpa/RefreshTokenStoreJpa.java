package com.lanny.spring_security_template.infrastructure.persistence.jpa;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.RefreshTokenEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.repository.RefreshTokenJpaRepository;
import com.lanny.spring_security_template.infrastructure.security.util.TokenHashUtil;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * JPA implementation of {@link RefreshTokenStore} with Token Rotation support.
 *
 * <p>
 * This adapter provides a <b>banking-grade</b> refresh token persistence model
 * based on:
 * </p>
 *
 * <ul>
 * <li>Hashed JWT IDs (JTI) — no clear-text tokens stored</li>
 * <li>Token rotation with family tracking</li>
 * <li>Reuse detection and automatic family revocation</li>
 * <li>Database-enforced uniqueness</li>
 * <li>Atomic operations to prevent race conditions</li>
 * </ul>
 *
 * <h2>Concurrency guarantees</h2>
 * <ul>
 * <li>Concurrent refresh attempts → only one succeeds</li>
 * <li>Double-spend prevented at database level</li>
 * <li>No reliance on transaction isolation alone</li>
 * </ul>
 *
 * <h2>Security Features</h2>
 * <ul>
 * <li><b>Family Tracking</b>: Groups rotated tokens from same auth session</li>
 * <li><b>Reuse Detection</b>: Automatically revokes family if revoked token is reused</li>
 * <li><b>Token Chaining</b>: Links tokens via previousTokenJti for audit trail</li>
 * <li><b>Explicit Revocation</b>: Supports logout and admin revocation</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
@Transactional
public class RefreshTokenStoreJpa implements RefreshTokenStore {

    private final RefreshTokenJpaRepository repo;

    /**
     * Stores a new refresh token session with family tracking.
     *
     * @param username          token owner
     * @param jti               refresh token JWT ID
     * @param familyId          family identifier grouping rotated tokens
     * @param previousTokenJti  JTI of the token that was rotated (null for initial token)
     * @param issuedAt          issuance timestamp
     * @param expiresAt         expiration timestamp
     */
    @Override
    public void save(String username, String jti, String familyId, String previousTokenJti, 
                     Instant issuedAt, Instant expiresAt) {

        RefreshTokenEntity entity = RefreshTokenEntity.builder()
                .username(username)
                .jtiHash(TokenHashUtil.hashJti(jti))
                .familyId(familyId)
                .previousTokenJti(previousTokenJti != null ? TokenHashUtil.hashJti(previousTokenJti) : null)
                .revoked(false)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .build();

        repo.save(entity);
    }

    /**
     * Finds a refresh token by its JTI.
     *
     * @param jti unique token identifier
     * @return optional containing token data if found
     */
    @Override
    public Optional<RefreshTokenData> findByJti(String jti) {
        String hash = TokenHashUtil.hashJti(jti);
        return repo.findByJtiHash(hash)
                .map(entity -> new RefreshTokenData(
                        entity.getJtiHash(), // Store hash, not clear-text JTI
                        entity.getUsername(),
                        entity.getFamilyId(),
                        entity.getPreviousTokenJti(),
                        entity.isRevoked(),
                        entity.getIssuedAt(),
                        entity.getExpiresAt()
                ));
    }

    /**
     * Revokes a specific refresh token by marking it as revoked.
     *
     * @param jti unique token identifier to revoke
     */
    @Override
    public void revoke(String jti) {
        String hash = TokenHashUtil.hashJti(jti);
        repo.revokeByHash(hash);
    }

    /**
     * Revokes all tokens in a family.
     * Used when reuse is detected — prevents attacker from using any token in the chain.
     *
     * @param familyId the family identifier to revoke
     */
    @Override
    public void revokeFamily(String familyId) {
        repo.revokeByFamilyId(familyId);
    }

    /**
     * Atomically consumes (revokes) a refresh token.
     *
     * <p>
     * This method guarantees that:
     * </p>
     * <ul>
     * <li>The refresh token can be used only once</li>
     * <li>Concurrent attempts result in a single success</li>
     * </ul>
     *
     * @param jti refresh token JWT ID
     * @return {@code true} if the token was successfully consumed,
     *         {@code false} otherwise
     * @deprecated Use {@link #findByJti(String)} + {@link #revoke(String)} for clearer semantics
     */
    @Override
    @Deprecated
    public boolean consume(String jti) {
        String hash = TokenHashUtil.hashJti(jti);
        return repo.revokeByHash(hash) == 1;
    }

    /**
     * Deletes all refresh tokens for a given user.
     *
     * @param username target user
     */
    @Override
    public void deleteAllForUser(String username) {
        repo.deleteByUsername(username);
    }

    /**
     * Returns all active refresh token hashes for a user.
     *
     * <p>
     * Intended for auditing or administrative purposes.
     * </p>
     */
    @Override
    public List<String> findAllForUser(String username) {
        return repo.findByUsername(username)
                .stream()
                .map(RefreshTokenEntity::getJtiHash)
                .toList();
    }

    /**
     * Deletes all expired refresh tokens.
     * Should be called by a scheduled cleanup job.
     *
     * @param before delete tokens that expired before this instant
     * @return number of tokens deleted
     */
    @Override
    public int deleteExpiredTokens(Instant before) {
        return repo.deleteByExpiresAtBefore(before);
    }
}
