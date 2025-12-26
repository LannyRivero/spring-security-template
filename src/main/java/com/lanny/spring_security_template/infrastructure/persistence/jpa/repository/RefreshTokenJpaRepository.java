package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.RefreshTokenEntity;

import io.micrometer.common.lang.NonNullApi;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@NonNullApi
public interface RefreshTokenJpaRepository extends JpaRepository<RefreshTokenEntity, Long> {

    /**
     * Finds a refresh token by its hashed JTI.
     */
    Optional<RefreshTokenEntity> findByJtiHash(String jtiHash);

    /**
     * Atomically revokes a token by its hash.
     * Returns the number of rows affected (1 if successful, 0 if already revoked or
     * not found).
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE RefreshTokenEntity r
                SET r.revoked = true
                WHERE r.jtiHash = :hash
                AND r.revoked = false
            """)
    int revokeByHash(@Param("hash") String hash);

    /**
     * Revokes all tokens in a family.
     * Used when reuse is detected.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("""
            UPDATE RefreshTokenEntity r
                SET r.revoked = true
                WHERE r.familyId = :familyId
                AND r.revoked = false
                """)
    int revokeByFamilyId(@Param("familyId") String familyId);

    /**
     * Finds all tokens for a specific user.
     */
    List<RefreshTokenEntity> findAllByUsername(String username);

    /**
     * Deletes all tokens for a specific user.
     */
    void deleteByUsername(String username);

    /**
     * Deletes all expired tokens.
     * Should be called by a scheduled cleanup job.
     */
    @Modifying(clearAutomatically = true, flushAutomatically = true)
    @Query("DELETE FROM RefreshTokenEntity r WHERE r.expiresAt < :before")
    int deleteByExpiresAtBefore(@Param("before") Instant before);
}
