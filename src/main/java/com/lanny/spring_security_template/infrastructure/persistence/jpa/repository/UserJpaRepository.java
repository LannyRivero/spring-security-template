package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.lang.NonNull;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.UserEntity;

/**
 * ============================================================
 * UserJpaRepository
 * ============================================================
 *
 * <p>
 * Infrastructure-level JPA repository for {@link UserEntity}.
 * </p>
 *
 * <p>
 * This repository is used exclusively by persistence adapters
 * and MUST NOT be referenced from domain or application layers.
 * </p>
 *
 * <h2>Design decisions</h2>
 * <ul>
 * <li>Only {@code roles} are eagerly fetched</li>
 * <li>Scopes are derived dynamically via {@code ScopePolicy}</li>
 * <li>All lookups are case-insensitive</li>
 * </ul>
 *
 * <h2>Contract</h2>
 * <ul>
 * <li>All parameters are non-null unless stated otherwise</li>
 * <li>Returned {@link Optional}s are never null</li>
 * </ul>
 */
public interface UserJpaRepository extends JpaRepository<UserEntity, String> {

    // ---------------------------------------------------------
    // LOGIN LOOKUP (username OR email)
    // ---------------------------------------------------------

    /**
     * Finds a user by username or email (case-insensitive).
     *
     * <p>
     * Used during authentication.
     * </p>
     */
    @EntityGraph(attributePaths = { "roles" })
    @Query("""
            SELECT u
              FROM UserEntity u
             WHERE LOWER(u.username) = LOWER(:value)
                OR LOWER(u.email) = LOWER(:value)
            """)
    Optional<UserEntity> findByUsernameOrEmail(@Param("value") @NonNull String value);

    // ---------------------------------------------------------
    // FIND BY USERNAME
    // ---------------------------------------------------------

    @EntityGraph(attributePaths = { "roles" })
    Optional<UserEntity> findByUsernameIgnoreCase(@NonNull String username);

    // ---------------------------------------------------------
    // FIND BY EMAIL
    // ---------------------------------------------------------

    @EntityGraph(attributePaths = { "roles" })
    Optional<UserEntity> findByEmailIgnoreCase(@NonNull String email);

    // ---------------------------------------------------------
    // EXISTS (validation / admin)
    // ---------------------------------------------------------

    boolean existsByUsernameIgnoreCase(@NonNull String username);

    boolean existsByEmailIgnoreCase(@NonNull String email);

    // ---------------------------------------------------------
    // FETCH WITH RELATIONS (admin / profile views)
    // ---------------------------------------------------------

    /**
     * Fetches a user with all required relations for administrative use.
     */
    @EntityGraph(attributePaths = { "roles" })
    @Query("""
            SELECT u
              FROM UserEntity u
             WHERE u.id = :id
            """)
    Optional<UserEntity> fetchWithRelations(@Param("id") @NonNull String id);
}
