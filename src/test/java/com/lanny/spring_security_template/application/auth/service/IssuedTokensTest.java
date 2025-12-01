package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.result.JwtResult;

class IssuedTokensTest {

        private static final Instant NOW = Instant.parse("2024-01-01T10:00:00Z");
        private static final Instant ACCESS_EXP = Instant.parse("2024-01-01T11:00:00Z");
        private static final Instant REFRESH_EXP = Instant.parse("2024-01-02T10:00:00Z");

        private static final List<String> ROLES = List.of("ADMIN", "USER");
        private static final List<String> SCOPES = List.of("read:profile", "write:profile");

        // ----------------------------------------------------------------------------------
        @Test
        @DisplayName("testShouldCreateRecordSuccessfully → Valid constructor values produce a correct IssuedTokens instance")
        void testShouldCreateRecordSuccessfully() {

                IssuedTokens tokens = new IssuedTokens(
                                "lanny",
                                "access-token-123",
                                "refresh-token-456",
                                "jti-abc",
                                NOW,
                                ACCESS_EXP,
                                REFRESH_EXP,
                                ROLES,
                                SCOPES);

                assertThat(tokens.username()).isEqualTo("lanny");
                assertThat(tokens.accessToken()).isEqualTo("access-token-123");
                assertThat(tokens.refreshToken()).isEqualTo("refresh-token-456");
                assertThat(tokens.refreshJti()).isEqualTo("jti-abc");
                assertThat(tokens.issuedAt()).isEqualTo(NOW);
                assertThat(tokens.accessExp()).isEqualTo(ACCESS_EXP);
                assertThat(tokens.refreshExp()).isEqualTo(REFRESH_EXP);
                assertThat(tokens.roleNames()).containsExactly("ADMIN", "USER");
                assertThat(tokens.scopeNames()).containsExactly("read:profile", "write:profile");
        }

        // ----------------------------------------------------------------------------------
        @Test
        @DisplayName("testShouldThrowWhenTimestampChronologyInvalid → issuedAt > accessExp OR accessExp > refreshExp must fail")
        void testShouldThrowWhenTimestampChronologyInvalid() {

                Instant badIssuedAt = ACCESS_EXP.plusSeconds(10);

                assertThatThrownBy(() -> new IssuedTokens(
                                "u",
                                "a",
                                "r",
                                "jti",
                                badIssuedAt, // issuedAt AFTER accessExp
                                ACCESS_EXP,
                                REFRESH_EXP,
                                ROLES,
                                SCOPES)).isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("chronology");

                Instant badAccessExp = REFRESH_EXP.plusSeconds(5);

                assertThatThrownBy(() -> new IssuedTokens(
                                "u",
                                "a",
                                "r",
                                "jti",
                                NOW,
                                badAccessExp, // accessExp AFTER refreshExp
                                REFRESH_EXP,
                                ROLES,
                                SCOPES)).isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("chronology");
        }

        // ----------------------------------------------------------------------------------
        @Test
        @DisplayName("testShouldThrowWhenRequiredFieldsAreNull → Null values must be rejected explicitly")
        void testShouldThrowWhenRequiredFieldsAreNull() {

                assertThatThrownBy(() -> new IssuedTokens(
                                null, "a", "r", "jti", NOW, ACCESS_EXP, REFRESH_EXP, ROLES, SCOPES))
                                .isInstanceOf(NullPointerException.class);

                assertThatThrownBy(() -> new IssuedTokens(
                                "u", null, "r", "jti", NOW, ACCESS_EXP, REFRESH_EXP, ROLES, SCOPES))
                                .isInstanceOf(NullPointerException.class);

                assertThatThrownBy(() -> new IssuedTokens(
                                "u", "a", null, "jti", NOW, ACCESS_EXP, REFRESH_EXP, ROLES, SCOPES))
                                .isInstanceOf(NullPointerException.class);

                assertThatThrownBy(() -> new IssuedTokens(
                                "u", "a", "r", "jti", null, ACCESS_EXP, REFRESH_EXP, ROLES, SCOPES))
                                .isInstanceOf(NullPointerException.class);

                assertThatThrownBy(() -> new IssuedTokens(
                                "u", "a", "r", "jti", NOW, null, REFRESH_EXP, ROLES, SCOPES))
                                .isInstanceOf(NullPointerException.class);

                assertThatThrownBy(() -> new IssuedTokens(
                                "u", "a", "r", "jti", NOW, ACCESS_EXP, null, ROLES, SCOPES))
                                .isInstanceOf(NullPointerException.class);
        }

        // ----------------------------------------------------------------------------------
        @Test
        @DisplayName("testShouldConvertToJwtResult → Conversion to JwtResult should preserve tokens and expiration")
        void testShouldConvertToJwtResult() {

                IssuedTokens tokens = new IssuedTokens(
                                "lanny",
                                "accessX",
                                "refreshY",
                                "jti",
                                NOW,
                                ACCESS_EXP,
                                REFRESH_EXP,
                                ROLES,
                                SCOPES);

                JwtResult result = tokens.toJwtResult();

                assertThat(result.accessToken()).isEqualTo("accessX");
                assertThat(result.refreshToken()).isEqualTo("refreshY");
                assertThat(result.expiresAt()).isEqualTo(ACCESS_EXP);
        }

        // ----------------------------------------------------------------------------------
        @Test
        @DisplayName("testShouldProduceAuditDetails → Audit string should contain key metadata")
        void testShouldProduceAuditDetails() {

                IssuedTokens tokens = new IssuedTokens(
                                "user1",
                                "a",
                                "r",
                                "jti",
                                NOW,
                                ACCESS_EXP,
                                REFRESH_EXP,
                                ROLES,
                                SCOPES);

                String audit = tokens.toAuditDetails();

                assertThat(audit)
                                .contains("user1")
                                .contains("ADMIN")
                                .contains("read:profile")
                                .contains(NOW.toString())
                                .contains(REFRESH_EXP.toString());
        }
}
