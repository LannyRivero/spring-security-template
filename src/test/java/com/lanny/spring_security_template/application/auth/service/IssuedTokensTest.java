package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.result.JwtResult;

/**
 * Unit tests for {@link IssuedTokens}.
 *
 * Focus: verify conversion to JwtResult and record integrity.
 * This record is a pure data holder, but correctness is critical
 * for token lifecycle flows (access + refresh).
 */
class IssuedTokensTest {

    @Test
    @DisplayName(" should correctly convert to JwtResult with matching fields")
    void testShouldConvertToJwtResultCorrectly() {
        Instant now = Instant.now();
        Instant accessExp = now.plusSeconds(600);
        Instant refreshExp = now.plusSeconds(3600);

        IssuedTokens tokens = new IssuedTokens(
                "lanny",
                "ACCESS_TOKEN",
                "REFRESH_TOKEN",
                "JTI-123",
                now,
                accessExp,
                refreshExp,
                List.of("ADMIN", "USER"),
                List.of("profile:read", "profile:write")
        );

        JwtResult result = tokens.toJwtResult();

        assertThat(result.accessToken()).isEqualTo("ACCESS_TOKEN");
        assertThat(result.refreshToken()).isEqualTo("REFRESH_TOKEN");
        assertThat(result.expiresAt()).isEqualTo(accessExp);
    }

    @Test
    @DisplayName(" should allow null tokens and propagate them in JwtResult")
    void testShouldPropagateNullValuesGracefully() {
        Instant exp = Instant.now().plusSeconds(120);
        IssuedTokens tokens = new IssuedTokens(
                "user",
                null,
                null,
                "JTI-XYZ",
                Instant.now(),
                exp,
                null,
                List.of(),
                List.of()
        );

        JwtResult result = tokens.toJwtResult();

        assertThat(result.accessToken()).isNull();
        assertThat(result.refreshToken()).isNull();
        assertThat(result.expiresAt()).isEqualTo(exp);
    }

    @Test
    @DisplayName(" should respect record equality and hashCode contract")
    void testShouldRespectRecordEqualityAndHashCode() {
        Instant now = Instant.now();

        IssuedTokens a = new IssuedTokens(
                "lanny",
                "AT",
                "RT",
                "JTI1",
                now,
                now.plusSeconds(100),
                now.plusSeconds(200),
                List.of("ADMIN"),
                List.of("scope:all")
        );

        IssuedTokens b = new IssuedTokens(
                "lanny",
                "AT",
                "RT",
                "JTI1",
                now,
                now.plusSeconds(100),
                now.plusSeconds(200),
                List.of("ADMIN"),
                List.of("scope:all")
        );

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    @DisplayName(" should store correct role and scope lists without mutation")
    void testShouldKeepRolesAndScopesImmutable() {
        Instant now = Instant.now();
        List<String> roles = List.of("ADMIN");
        List<String> scopes = List.of("profile:read");

        IssuedTokens tokens = new IssuedTokens(
                "lanny",
                "AT",
                "RT",
                "JTI",
                now,
                now.plusSeconds(100),
                now.plusSeconds(200),
                roles,
                scopes
        );

        assertThat(tokens.roleNames()).containsExactly("ADMIN");
        assertThat(tokens.scopeNames()).containsExactly("profile:read");

        // Verify immutability (record stores by reference, but we rely on List.of() immutability)
        assertThatThrownBy(() -> tokens.roleNames().add("NEW_ROLE"))
                .isInstanceOf(UnsupportedOperationException.class);
    }
}

