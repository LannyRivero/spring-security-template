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
import java.util.Objects;
import java.util.Optional;

/**
 * JPA implementation of {@link RefreshTokenStore} supporting
 * <b>family-based refresh token rotation</b>.
 *
 * <p>
 * This adapter provides a <b>production-grade</b> persistence model
 * for refresh tokens with the following guarantees:
 * </p>
 *
 * <ul>
 * <li><b>No clear-text tokens stored</b> — only hashed JTIs are persisted</li>
 * <li><b>Token family tracking</b> for rotation and reuse detection</li>
 * <li><b>Explicit revocation</b> of individual tokens or entire families</li>
 * <li><b>Database-enforced atomicity</b> for concurrent refresh attempts</li>
 * </ul>
 *
 * <h2>Concurrency & Security</h2>
 * <ul>
 * <li>Concurrent refresh attempts result in a single valid rotation</li>
 * <li>Reuse of a revoked token can trigger full family revocation</li>
 * <li>No reliance on JVM memory or in-process state</li>
 * </ul>
 *
 * <p>
 * This adapter is suitable for <b>banking-grade systems</b> and complies
 * with OWASP ASVS recommendations for refresh token handling.
 * </p>
 */
@Component
@RequiredArgsConstructor
@Transactional
public class RefreshTokenStoreJpa implements RefreshTokenStore {

    private final RefreshTokenJpaRepository repo;

    /**
     * Persists a newly issued refresh token with family metadata.
     *
     * <p>
     * The provided {@code jti} and {@code previousTokenJti} are
     * <b>hashed before persistence</b> to avoid storing sensitive identifiers.
     * </p>
     *
     * @param username         token owner
     * @param jti              refresh token JWT ID (clear-text, will be hashed)
     * @param familyId         family identifier grouping rotated tokens
     * @param previousTokenJti JTI of the rotated token (nullable)
     * @param issuedAt         issuance timestamp
     * @param expiresAt        expiration timestamp
     */
    @Override
    public void save(
            String username,
            String jti,
            String familyId,
            String previousTokenJti,
            Instant issuedAt,
            Instant expiresAt) {

        RefreshTokenEntity entity = RefreshTokenEntity.builder()
                .username(username)
                .jtiHash(TokenHashUtil.hashJti(jti))
                .familyId(familyId)
                .previousTokenJti(
                        previousTokenJti != null
                                ? TokenHashUtil.hashJti(previousTokenJti)
                                : null)
                .revoked(false)
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .build();

        repo.save(Objects.requireNonNull(entity, "RefreshTokenEntity must not be null"));
    }

    /**
     * Retrieves refresh token metadata by its JWT ID.
     *
     * <p>
     * Internally, the provided JTI is hashed and matched against
     * the persisted value.
     * </p>
     *
     * @param jti refresh token JWT ID (clear-text)
     * @return optional refresh token metadata if found
     */
    @Override
    public Optional<RefreshTokenData> findByJti(String jti) {
        String hash = TokenHashUtil.hashJti(jti);

        return repo.findByJtiHash(Objects.requireNonNull(hash, "Hashed JTI must not be null"))
                .map(entity -> new RefreshTokenData(
                        entity.getJtiHash(), // hash, never clear-text
                        entity.getUsername(),
                        entity.getFamilyId(),
                        entity.getPreviousTokenJti(), // hash
                        entity.isRevoked(),
                        entity.getIssuedAt(),
                        entity.getExpiresAt()));
    }

    /**
     * Revokes a specific refresh token.
     *
     * <p>
     * This operation is idempotent — revoking an already revoked token
     * has no additional effect.
     * </p>
     *
     * @param refreshJti refresh token JWT ID (clear-text)
     */
    @Override
    public void revoke(String refreshJti) {

        repo.revokeByHash(Objects.requireNonNull(TokenHashUtil.hashJti(refreshJti), "Hashed JTI must not be null"));
    }

    /**
     * Revokes all refresh tokens belonging to the given family.
     *
     * <p>
     * Used when refresh token reuse is detected, effectively invalidating
     * the entire authentication session chain.
     * </p>
     *
     * @param familyId token family identifier
     */
    @Override
    public void revokeFamily(String familyId) {
        repo.revokeByFamilyId(Objects.requireNonNull(familyId, "Family ID must not be null"));
    }

    /**
     * Deletes all refresh tokens associated with the given user.
     *
     * <p>
     * Typically used for:
     * </p>
     * <ul>
     * <li>"Logout all devices"</li>
     * <li>Account deactivation or deletion</li>
     * </ul>
     *
     * @param username target user
     */
    @Override
    public void deleteAllForUser(String username) {
        repo.deleteByUsername(Objects.requireNonNull(username, "Username must not be null"));
    }

    /**
     * Retrieves all active refresh token hashes for a user.
     *
     * <p>
     * Intended strictly for auditing or administrative inspection.
     * The returned values are <b>hashed identifiers</b>, not usable
     * for authentication.
     * </p>
     *
     * @param username target user
     * @return list of refresh token JTI hashes
     */
    @Override
    public List<String> findAllForUser(String username) {
        return repo.findAllByUsername(Objects.requireNonNull(username, "Username must not be null"))
                .stream()
                .map(RefreshTokenEntity::getJtiHash)
                .toList();
    }

    /**
     * Deletes all refresh tokens that expired before the given instant.
     *
     * <p>
     * Intended to be executed by a scheduled cleanup job.
     * </p>
     *
     * @param before expiration cutoff
     * @return number of deleted tokens
     */
    @Override
    public int deleteExpiredTokens(Instant before) {
        return repo.deleteByExpiresAtBefore(Objects.requireNonNull(before, "Expiration cutoff must not be null"));
    }
}
