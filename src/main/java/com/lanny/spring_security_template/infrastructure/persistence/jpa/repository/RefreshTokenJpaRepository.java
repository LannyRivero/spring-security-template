package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.lang.NonNull;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.RefreshTokenEntity;

/**
 * ============================================================
 * RefreshTokenJpaRepository
 * ============================================================
 *
 * <p>
 * JPA repository for persisted refresh tokens with support for:
 * </p>
 * <ul>
 * <li>Token rotation</li>
 * <li>Reuse detection (family-based)</li>
 * <li>Explicit revocation</li>
 * <li>Offline cleanup of expired tokens</li>
 * </ul>
 *
 * <h2>Important</h2>
 * <p>
 * This repository is <b>NOT</b> used for runtime authorization checks.
 * Runtime enforcement is handled by Redis for performance and distribution.
 * </p>
 *
 * <p>
 * JPA persistence is used to:
 * </p>
 * <ul>
 * <li>Maintain refresh token rotation history</li>
 * <li>Detect reuse across sessions</li>
 * <li>Provide auditable security state</li>
 * </ul>
 *
 * <h2>Contract</h2>
 * <ul>
 * <li>All parameters are non-null unless stated otherwise</li>
 * <li>All modifying queries are atomic at database level</li>
 * </ul>
 */
public interface RefreshTokenJpaRepository
        extends JpaRepository<RefreshTokenEntity, Long> {

    /**
     * Finds a refresh token by its hashed JWT ID.
     *
     * @param jtiHash hashed JTI (non-null)
     * @return optional refresh token entity
     */
    Optional<RefreshTokenEntity> findByJtiHash(@NonNull String jtiHash);

    /**
     * Atomically revokes a single refresh token by its hashed JTI.
     *
     * <p>
     * Used during normal rotation.
     * </p>
     *
     * @param hash hashed JTI (non-null)
     * @return number of rows updated (1 = revoked, 0 = already revoked or not
     *         found)
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE RefreshTokenEntity r
               SET r.revoked = true
             WHERE r.jtiHash = :hash
               AND r.revoked = false
            """)
    int revokeByHash(@Param("hash") @NonNull String hash);

    /**
     * Revokes all refresh tokens belonging to the same family.
     *
     * <p>
     * Used when reuse is detected to invalidate the entire token chain.
     * </p>
     *
     * @param familyId token family identifier (non-null)
     * @return number of rows updated
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE RefreshTokenEntity r
               SET r.revoked = true
             WHERE r.familyId = :familyId
               AND r.revoked = false
            """)
    int revokeByFamilyId(@Param("familyId") @NonNull String familyId);

    /**
     * Finds all refresh tokens for a given user.
     *
     * @param username username (non-null)
     * @return list of tokens (never null)
     */
    List<RefreshTokenEntity> findAllByUsername(@NonNull String username);

    /**
     * Deletes all refresh tokens for a given user.
     *
     * <p>
     * Typically used on logout-all or account deletion.
     * </p>
     *
     * @param username username (non-null)
     */
    void deleteByUsername(@NonNull String username);

    /**
     * Deletes all expired refresh tokens.
     *
     * <p>
     * Intended for execution by a scheduled maintenance job.
     * </p>
     *
     * @param before cutoff instant (non-null)
     * @return number of rows deleted
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            DELETE FROM RefreshTokenEntity r
             WHERE r.expiresAt < :before
            """)
    int deleteByExpiresAtBefore(@Param("before") @NonNull Instant before);
}
