package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import static org.assertj.core.api.Assertions.*;

import org.hibernate.exception.ConstraintViolationException;

import java.util.Objects;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.test.context.ActiveProfiles;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.RoleEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.ScopeEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.UserEntity;

/**
 * Test suite for {@link UserJpaRepository}.
 *
 * <p>
 * Uses {@link DataJpaTest} with H2 in-memory database to validate:
 * <ul>
 * <li>Query methods (findByUsername, findByEmail, findByUsernameOrEmail)</li>
 * <li>Unique constraints (username, email)</li>
 * <li>Entity graph loading (N+1 prevention)</li>
 * <li>Transaction rollback on constraint violations</li>
 * <li>Case-insensitive queries</li>
 * </ul>
 *
 * <p>
 * <b>Scope:</b> Persistence layer only (infrastructure).
 * <p>
 * <b>Profile:</b> test (H2 database)
 * <p>
 * <b>Coverage Goal:</b> 100% of repository methods
 */

@DataJpaTest
@ActiveProfiles("test")
@EnableJpaRepositories(basePackageClasses = UserJpaRepository.class)
@DisplayName("UserJpaRepository Tests")
public class UserJpaRepositoryTest {

    @Autowired
    private UserJpaRepository userJpaRepository;

    @Autowired
    private TestEntityManager entityManager;

    private RoleEntity adminRole;
    private RoleEntity userRole;
    private ScopeEntity profileReadScope;
    private ScopeEntity profileWriteScope;

    @BeforeEach
    void setUp() {
        adminRole = new RoleEntity("ROLE_ADMIN");
        userRole = new RoleEntity("ROLE_USER");
        entityManager.persist(adminRole);
        entityManager.persist(userRole);

        profileReadScope = new ScopeEntity("profile:read");
        profileWriteScope = new ScopeEntity("profile:write");
        entityManager.persist(profileReadScope);
        entityManager.persist(profileWriteScope);

        entityManager.flush();
    }

    // =========================================================================
    // HAPPY PATH TESTS
    // =========================================================================

    @Nested
    @DisplayName("Happy Path - Query Methods")
    class HappyPathQueryTests {
        @Test
        @DisplayName("Should save user successfully")
        void testShouldSaveUserSuccessfully() {
            UserEntity user = Objects.requireNonNull(UserTestData.defaultUser());

            UserEntity saved = userJpaRepository.save(user);
            entityManager.flush();

            assertThat(saved).isNotNull();
            assertThat(saved.getId()).isNotNull();
            assertThat(saved.getUsername()).isEqualTo(UserTestData.USERNAME);
            assertThat(saved.getEmail()).isEqualTo(UserTestData.EMAIL);
            assertThat(saved.isEnabled()).isTrue();
        }

        @Test
        @DisplayName("Should find user by username ignoring case")
        void testShouldFindUserByUsernameIgnoreCase() {
            givenPersistedUser();

            Optional<UserEntity> found = userJpaRepository.findByUsernameIgnoreCase(UserTestData.USERNAME_UPPER);
            assertThat(found).isPresent();
        }

        @Test
        @DisplayName("Should find user by email ignoring case")
        void testShouldFindUserByEmailIgnoreCase() {

            givenPersistedUser();
            Optional<UserEntity> found = userJpaRepository.findByEmailIgnoreCase(UserTestData.EMAIL_UPPER);
            assertThat(found).isPresent();
            assertThat(found.get().getEmail()).isEqualTo(UserTestData.EMAIL);
        }

        @Test
        @DisplayName("Should find user by username or email with username")
        void testShouldFindUserByUsernameOrEmailWithUsername() {

            givenPersistedUser();
            Optional<UserEntity> found = userJpaRepository.findByUsernameOrEmail(UserTestData.USERNAME);
            assertThat(found).isPresent();
            assertThat(found.get().getUsername()).isEqualTo(UserTestData.USERNAME);
        }

        @Test
        @DisplayName("Should find user by username or email with email")
        void testShouldFindUserByUsernameOrEmailWithEmail() {

            givenPersistedUser();
            Optional<UserEntity> found = userJpaRepository.findByUsernameOrEmail(UserTestData.EMAIL);
            assertThat(found).isPresent();
            assertThat(found.get().getEmail()).isEqualTo(UserTestData.EMAIL);
        }

        @Test
        @DisplayName("Should fetch user with relations")
        void testShouldFetchUserWithRelations() {

            UserEntity saved = givenPersistedUserWithRelations();

            Optional<UserEntity> found = userJpaRepository.fetchWithRelations(Objects.requireNonNull(saved.getId()));

            assertThat(found).isPresent();
            assertThat(found.get().getRoles()).hasSize(1);
        }

        @Test
        @DisplayName("Should return true when username exists")
        void testShouldReturnTrueWhenUsernameExists() {

            givenPersistedUser();

            boolean exists = userJpaRepository.existsByUsernameIgnoreCase(
                    UserTestData.USERNAME_UPPER);

            assertThat(exists).isTrue();
        }

        @Test
        @DisplayName("Should return true when email exists")
        void testShouldReturnTrueWhenEmailExists() {

            givenPersistedUser();

            boolean exists = userJpaRepository.existsByEmailIgnoreCase(
                    UserTestData.EMAIL_UPPER);

            assertThat(exists).isTrue();
        }

        @Test
        @DisplayName("Should return false when username does not exist")
        void testShouldReturnFalseWhenUsernameDoesNotExist() {

            boolean exists = userJpaRepository.existsByUsernameIgnoreCase("nonexistent");

            assertThat(exists).isFalse();
        }

        @Test
        @DisplayName("Should return false when email does not exist")
        void testShouldReturnFalseWhenEmailDoesNotExist() {

            boolean exists = userJpaRepository.existsByEmailIgnoreCase(
                    "nonexistent@example.com");

            assertThat(exists).isFalse();
        }

        @Test
        @DisplayName("Should return empty when user not found by username")
        void testShouldReturnEmptyWhenUserNotFoundByUsername() {

            Optional<UserEntity> found = userJpaRepository.findByUsernameIgnoreCase("nonexistent");

            assertThat(found).isEmpty();
        }

        @Test
        @DisplayName("Should return empty when user not found by email")
        void testShouldReturnEmptyWhenUserNotFoundByEmail() {

            Optional<UserEntity> found = userJpaRepository.findByEmailIgnoreCase(
                    "nonexistent@example.com");

            assertThat(found).isEmpty();
        }

        @Test
        @DisplayName("Should return empty when user not found by username or email")
        void testShouldReturnEmptyWhenUserNotFoundByUsernameOrEmail() {

            Optional<UserEntity> found = userJpaRepository.findByUsernameOrEmail(
                    "nonexistent");

            assertThat(found).isEmpty();
        }

    }

    // =========================================================================
    // CONSTRAINT TESTS
    // =========================================================================
    @Nested
    @DisplayName("Constraint Validation Tests")
    class ConstraintTests {

        @Test
        @DisplayName("Should fail when username is not unique")
        void testShouldFailWhenUsernameIsNotUnique() {

            givenPersistedUserWithUsername("duplicate");

            UserEntity duplicate = UserTestData.defaultUser();
            duplicate.setUsername("duplicate");
            duplicate.setEmail("other@example.com");

            assertThatThrownBy(() -> {
                userJpaRepository.save(duplicate);
                entityManager.flush();
            }).isInstanceOf(ConstraintViolationException.class);
        }

        @Test
        @DisplayName("Should fail when email is not unique")
        void testShouldFailWhenEmailIsNotUnique() {

            givenPersistedUserWithEmail("duplicate@example.com");

            UserEntity duplicate = UserTestData.defaultUser();
            duplicate.setUsername("other_user");
            duplicate.setEmail("duplicate@example.com");

            assertThatThrownBy(() -> {
                userJpaRepository.save(duplicate);
                entityManager.flush();
            }).isInstanceOf(ConstraintViolationException.class);
        }

        @Test
        @DisplayName("Should fail when username is null")
        void shouldFailWhenUsernameIsNull() {

            UserEntity user = UserTestData.defaultUser();
            user.setUsername(null);

            assertThatThrownBy(() -> {
                userJpaRepository.save(user);
                entityManager.flush();
            }).isInstanceOf(ConstraintViolationException.class);
        }

        @Test
        @DisplayName("Should fail when email is null")
        void shouldFailWhenEmailIsNull() {

            UserEntity user = UserTestData.defaultUser();
            user.setEmail(null);

            assertThatThrownBy(() -> {
                userJpaRepository.save(user);
                entityManager.flush();
            }).isInstanceOf(ConstraintViolationException.class);
        }

        @Test
        @DisplayName("Should fail when password hash is null")
        void shouldFailWhenPasswordHashIsNull() {

            UserEntity user = UserTestData.defaultUser();
            user.setPasswordHash(null);

            assertThatThrownBy(() -> {
                userJpaRepository.save(user);
                entityManager.flush();
            }).isInstanceOf(ConstraintViolationException.class);
        }

    }

    // =========================================================================
    // TRANSACTION TESTS
    // =========================================================================
    @Nested
    @DisplayName("Transaction Rollback Tests")
    class TransactionTests {
        @Test
        @DisplayName("Should rollback transaction on constraint violation")
        void shouldRollbackTransactionOnConstraintViolation() {

            givenPersistedUserWithUsername("original");

            long countBefore = userJpaRepository.count();

            assertThatThrownBy(() -> {
                UserEntity duplicate = UserTestData.defaultUser();
                duplicate.setUsername("original");
                duplicate.setEmail("different@example.com");

                userJpaRepository.save(duplicate);
                entityManager.flush();
            }).hasRootCauseInstanceOf(
                    org.h2.jdbc.JdbcSQLIntegrityConstraintViolationException.class);

            long countAfter = userJpaRepository.count();
            assertThat(countAfter).isEqualTo(countBefore);
        }

    }

    // =========================================================================
    // EDGE CASES
    // =========================================================================
    @Nested
    @DisplayName("Edge Cases")
    class EdgeCaseTests {
        @Test
        @DisplayName("Should return empty optional when user not found")
        void shouldReturnEmptyOptionalWhenUserNotFound() {

            Optional<UserEntity> found = userJpaRepository.findByUsernameIgnoreCase("nonexistent");

            assertThat(found).isEmpty();
        }

        @Test
        @DisplayName("Should handle user with empty roles and scopes")
        void shouldHandleUserWithEmptyRolesAndScopes() {

            UserEntity user = UserTestData.defaultUser();
            user.setUsername("minimaluser");
            user.setEmail("minimal@example.com");

            entityManager.persistAndFlush(user);
            entityManager.clear();

            Optional<UserEntity> found = userJpaRepository.findByUsernameIgnoreCase("minimaluser");

            assertThat(found).isPresent();
            assertThat(found.get().getRoles()).isEmpty();
        }

        @Test
        @DisplayName("Should handle special characters in username")
        void shouldHandleSpecialCharactersInUsername() {

            UserEntity user = UserTestData.defaultUser();
            user.setUsername("user.name-123_test");
            user.setEmail("special@example.com");

            entityManager.persistAndFlush(user);

            Optional<UserEntity> found = userJpaRepository.findByUsernameIgnoreCase("user.name-123_test");

            assertThat(found).isPresent();
            assertThat(found.get().getUsername())
                    .isEqualTo("user.name-123_test");
        }

        @Test
        @DisplayName("Should handle long email addresses")
        void shouldHandleLongEmailAddresses() {

            String longEmail = "a".repeat(140) + "@test.com";

            UserEntity user = UserTestData.defaultUser();
            user.setUsername("longuser");
            user.setEmail(longEmail);

            entityManager.persistAndFlush(user);

            Optional<UserEntity> found = userJpaRepository.findByEmailIgnoreCase(longEmail);

            assertThat(found).isPresent();
        }

    }
    // =========================================================================
    // TEST DATA HELPERS
    // =========================================================================

    private UserEntity givenPersistedUser() {
        return entityManager.persistAndFlush(UserTestData.defaultUser());
    }

    private UserEntity givenPersistedUserWithRelations() {
        UserEntity user = UserTestData.defaultUser();
        user.getRoles().add(adminRole);
        return entityManager.persistAndFlush(user);
    }

    private UserEntity givenPersistedUserWithUsername(String username) {
        UserEntity user = UserTestData.defaultUser();
        user.setUsername(username);
        return entityManager.persistAndFlush(user);
    }

    private UserEntity givenPersistedUserWithEmail(String email) {
        UserEntity user = UserTestData.defaultUser();
        user.setEmail(email);
        return entityManager.persistAndFlush(user);
    }

}
