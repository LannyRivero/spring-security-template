package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import java.time.Instant;
import java.util.List;

import org.springframework.context.annotation.Profile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.lang.NonNull;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.BlacklistedTokenEntity;

/**
 * ============================================================
 * BlacklistedTokenJpaRepository
 * ============================================================
 *
 * <p>
 * JPA repository for persisted token revocations (blacklist entries).
 * </p>
 *
 * <h2>IMPORTANT</h2>
 * <p>
 * The default revocation strategy of this template is Redis + TTL
 * (fast enforcement, distributed, no cleanup jobs).
 * </p>
 *
 * <p>
 * This repository is therefore intended ONLY for audit/forensics
 * or regulated environments where persisted revocation evidence is required.
 * </p>
 *
 * <h2>Profile</h2>
 * <ul>
 * <li>Enabled only under {@code audit}</li>
 * </ul>
 *
 * <h2>Contract</h2>
 * <ul>
 * <li>Caller must provide non-null inputs</li>
 * <li>Repository performs persistence only (no business rules)</li>
 * </ul>
 */
@Profile("audit")
public interface BlacklistedTokenJpaRepository
        extends JpaRepository<BlacklistedTokenEntity, Long> {

    /**
     * Finds blacklist entries that have already expired.
     *
     * <p>
     * Intended for offline cleanup jobs (e.g. scheduled maintenance).
     * </p>
     *
     * @param now current timestamp (non-null)
     * @return list of expired entries (never null)
     */
    List<BlacklistedTokenEntity> findByExpiresAtBefore(@NonNull Instant now);

    /**
     * Deletes a blacklist entry by its JWT ID (jti).
     *
     * @param jti token identifier (non-null)
     */
    void deleteByJti(@NonNull String jti);
}
