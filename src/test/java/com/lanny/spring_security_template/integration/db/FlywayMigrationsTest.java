package com.lanny.spring_security_template.integration.db;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.assertj.core.api.Assertions.*;

/**
 * Integration tests validating Flyway database migrations.
 *
 * <p>Scope:
 * <ul>
 *   <li>Migration execution and ordering</li>
 *   <li>Schema structure and constraints</li>
 *   <li>Seed data correctness</li>
 *   <li>Indexes and foreign keys</li>
 * </ul>
 *
 * <p>Database: H2 (test profile)
 */
@JdbcTest
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@DisplayName("Flyway Migrations Integration Tests")
class FlywayMigrationsTest {


    @Autowired
    private JdbcTemplate jdbcTemplate;

    // =========================================================================
    // SETUP
    // =========================================================================


    
    // =========================================================================
    // SCHEMA VALIDATION (V1)
    // =========================================================================

    @Nested
    @DisplayName("Schema Validation - Core Tables")
    class SchemaValidationTests {

        @Test
        @DisplayName("Should create users table with correct columns")
        void shouldCreateUsersTable() {
            assertThat(getColumnNames("users"))
                .containsExactlyInAnyOrder(
                    "id", "username", "email", "password_hash", "enabled", "status"
                );
        }

        @Test
        @DisplayName("Should create roles table")
        void shouldCreateRolesTable() {
            assertThat(getColumnNames("roles"))
                .containsExactlyInAnyOrder("id", "name");
        }

        @Test
        @DisplayName("Should create scopes table")
        void shouldCreateScopesTable() {
            assertThat(getColumnNames("scopes"))
                .containsExactlyInAnyOrder("id", "name");
        }

        @Test
        @DisplayName("Should create user_roles junction table")
        void shouldCreateUserRolesTable() {
            assertThat(getColumnNames("user_roles"))
                .containsExactlyInAnyOrder("user_id", "role_id");
        }

        @Test
        @DisplayName("Should create role_scopes junction table")
        void shouldCreateRoleScopesTable() {
            assertThat(getColumnNames("role_scopes"))
                .containsExactlyInAnyOrder("role_id", "scope_id");
        }
    }

    // =========================================================================
    // CONSTRAINT VALIDATION
    // =========================================================================

    @Nested
    @DisplayName("Constraint Validation")
    class ConstraintTests {

        @Test
        @DisplayName("Should enforce unique username")
        void shouldEnforceUniqueUsername() {
            insertUser("user1", "a@test.com");

            assertThatThrownBy(() ->
                insertUser("user1", "b@test.com")
            ).isInstanceOf(DataIntegrityViolationException.class);
        }

        @Test
        @DisplayName("Should enforce unique email")
        void shouldEnforceUniqueEmail() {
            insertUser("user1", "a@test.com");

            assertThatThrownBy(() ->
                insertUser("user2", "a@test.com")
            ).isInstanceOf(DataIntegrityViolationException.class);
        }

        @Test
        @DisplayName("Should enforce NOT NULL constraints")
        void shouldEnforceNotNullConstraints() {
            assertThatThrownBy(() ->
                jdbcTemplate.update(
                    "INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)",
                    UUID.randomUUID().toString(),
                    null,
                    "test@test.com",
                    "hash"
                )
            ).isInstanceOf(DataIntegrityViolationException.class);
        }
    }

    // =========================================================================
    // SEED DATA VALIDATION
    // =========================================================================

    @Nested
    @DisplayName("Seed Data Validation")
    class SeedDataTests {

        @Test
        @DisplayName("Should seed default roles")
        void shouldSeedRoles() {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM roles",
                Integer.class
            );

            assertThat(count).isGreaterThanOrEqualTo(2);
        }

        @Test
        @DisplayName("Should seed default scopes")
        void shouldSeedScopes() {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM scopes",
                Integer.class
            );

            assertThat(count).isGreaterThan(0);
        }

        @Test
        @DisplayName("Should seed role-scope relations")
        void shouldSeedRoleScopes() {
            Integer count = jdbcTemplate.queryForObject(
                "SELECT COUNT(*) FROM role_scopes",
                Integer.class
            );

            assertThat(count).isGreaterThan(0);
        }
    }

    // =========================================================================
    // REFRESH TOKEN TABLE VALIDATION
    // =========================================================================

    @Nested
    @DisplayName("Refresh Token Schema")
    class RefreshTokenTests {

        @Test
        @DisplayName("Should create refresh_tokens table")
        void shouldCreateRefreshTokensTable() {
            assertThat(getColumnNames("refresh_tokens"))
                .contains(
                    "id", "username", "issued_at", "expires_at",
                    "jti_hash", "family_id", "previous_token_jti", "revoked"
                );
        }

        @Test
        @DisplayName("Should enforce unique jti_hash")
        void shouldEnforceUniqueJtiHash() {
            insertRefreshToken("hash-1");

            assertThatThrownBy(() ->
                insertRefreshToken("hash-1")
            ).isInstanceOf(DataIntegrityViolationException.class);
        }

        @Test
        @DisplayName("Should have indexes on refresh_tokens")
        void shouldHaveIndexes() {
            List<Map<String, Object>> indexes =
                jdbcTemplate.queryForList(
                    """
                    SELECT INDEX_NAME
                    FROM INFORMATION_SCHEMA.INDEXES
                    WHERE TABLE_NAME = 'REFRESH_TOKENS'
                    """
                );

            assertThat(indexes)
                .extracting(i -> i.get("INDEX_NAME").toString().toLowerCase())
                .anyMatch(name -> name.contains("jti"));
        }
    }

    // =========================================================================
    // HELPER METHODS
    // =========================================================================

    private List<String> getColumnNames(String table) {
        return jdbcTemplate.queryForList(
            """
            SELECT COLUMN_NAME
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_NAME = ?
            ORDER BY ORDINAL_POSITION
            """,
            String.class,
            table.toUpperCase()
        );
    }

    private void insertUser(String username, String email) {
        jdbcTemplate.update(
            "INSERT INTO users (id, username, email, password_hash) VALUES (?, ?, ?, ?)",
            UUID.randomUUID().toString(),
            username,
            email,
            "hash"
        );
    }

    private void insertRefreshToken(String jtiHash) {
        jdbcTemplate.update(
            """
            INSERT INTO refresh_tokens
            (username, jti_hash, family_id, revoked, issued_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            "user",
            jtiHash,
            "family",
            false,
            Instant.now(),
            Instant.now().plusSeconds(3600)
        );
    }
}
