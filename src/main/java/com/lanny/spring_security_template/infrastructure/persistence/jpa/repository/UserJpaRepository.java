package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.UserEntity;

/**
 * JPA repository for {@link UserEntity}.
 *
 * This interface belongs strictly to the infrastructure layer and provides
 * data-access methods required by the UserAccountGateway adapter.
 *
 * Notes:
 * - All queries are case-insensitive.
 * - Fetch roles/scopes with EntityGraph to avoid N+1 issues.
 * - The service layer or domain layer never depends on this interface.
 */
public interface UserJpaRepository extends JpaRepository<UserEntity, String> {

    // -------------------------------------------------------------------------
    // LOGIN LOOKUP (username OR email)
    // -------------------------------------------------------------------------
    @EntityGraph(attributePaths = { "roles", "scopes" })
    @Query("""
            SELECT u
            FROM UserEntity u
            WHERE LOWER(u.username) = LOWER(:value)
               OR LOWER(u.email) = LOWER(:value)
            """)
    Optional<UserEntity> findByUsernameOrEmail(@Param("value") String value);

    // -------------------------------------------------------------------------
    // FIND BY USERNAME
    // -------------------------------------------------------------------------
    @EntityGraph(attributePaths = { "roles", "scopes" })
    Optional<UserEntity> findByUsernameIgnoreCase(String username);

    // -------------------------------------------------------------------------
    // FIND BY EMAIL
    // -------------------------------------------------------------------------
    @EntityGraph(attributePaths = { "roles", "scopes" })
    Optional<UserEntity> findByEmailIgnoreCase(String email);

    // -------------------------------------------------------------------------
    // EXISTS (useful for validations or admin panel)
    // -------------------------------------------------------------------------
    boolean existsByUsernameIgnoreCase(String username);

    boolean existsByEmailIgnoreCase(String email);

    // -------------------------------------------------------------------------
    // FETCH WITH RELATIONS (admin use)
    // -------------------------------------------------------------------------
    @EntityGraph(attributePaths = { "roles", "scopes" })
    @Query("SELECT u FROM UserEntity u WHERE u.id = :id")
    Optional<UserEntity> fetchWithRelations(@Param("id") String id);
}
