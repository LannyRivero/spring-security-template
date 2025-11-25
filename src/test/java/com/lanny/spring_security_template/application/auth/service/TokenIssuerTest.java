package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;

/**
 * Unit tests for {@link TokenIssuer}.
 * Verifies token issuance, expiration times and delegation.
 */
class TokenIssuerTest {

    private TokenProvider tokenProvider;
    private ClockProvider clockProvider;
    private SecurityJwtProperties props;
    private TokenIssuer tokenIssuer;

    private static final String USERNAME = "lanny";

    private final RoleScopeResult rs = new RoleScopeResult(
            List.of("ROLE_USER"),
            List.of("profile:read"));

    private final Instant fixedNow = Instant.parse("2030-01-01T00:00:00Z");
    private final Duration accessTtl = Duration.ofMinutes(15);
    private final Duration refreshTtl = Duration.ofDays(7);

    @BeforeEach
    void setUp() {
        tokenProvider = mock(TokenProvider.class);
        clockProvider = mock(ClockProvider.class);
        props = mock(SecurityJwtProperties.class);

        tokenIssuer = new TokenIssuer(tokenProvider, clockProvider, props);

        when(clockProvider.now()).thenReturn(fixedNow);
        when(props.accessTtl()).thenReturn(accessTtl);
        when(props.refreshTtl()).thenReturn(refreshTtl);
    }

    @Test
    @DisplayName(" should issue valid access and refresh tokens with correct expiration times")
    void testShouldIssueTokensCorrectly() {
        // Arrange
        when(tokenProvider.generateAccessToken(USERNAME, rs.roleNames(), rs.scopeNames(), accessTtl))
                .thenReturn("access-token-xyz");

        when(tokenProvider.generateRefreshToken(USERNAME, refreshTtl))
                .thenReturn("refresh-token-abc");

        when(tokenProvider.extractJti("refresh-token-abc"))
                .thenReturn("jti-123");

        // Act
        IssuedTokens tokens = tokenIssuer.issueTokens(USERNAME, rs);

        // Assert
        assertThat(tokens.username()).isEqualTo(USERNAME);
        assertThat(tokens.accessToken()).isEqualTo("access-token-xyz");
        assertThat(tokens.refreshToken()).isEqualTo("refresh-token-abc");
        assertThat(tokens.refreshJti()).isEqualTo("jti-123");

        assertThat(tokens.issuedAt()).isEqualTo(fixedNow);
        assertThat(tokens.accessExp()).isEqualTo(fixedNow.plus(accessTtl));
        assertThat(tokens.refreshExp()).isEqualTo(fixedNow.plus(refreshTtl));

        assertThat(tokens.roleNames()).containsExactly("ROLE_USER");
        assertThat(tokens.scopeNames()).containsExactly("profile:read");

        verify(tokenProvider).generateAccessToken(USERNAME, rs.roleNames(), rs.scopeNames(), accessTtl);
        verify(tokenProvider).generateRefreshToken(USERNAME, refreshTtl);
        verify(tokenProvider).extractJti("refresh-token-abc");
    }

    @Test
    @DisplayName(" should handle missing scopes or roles gracefully")
    void testShouldHandleEmptyScopesOrRoles() {
        RoleScopeResult empty = new RoleScopeResult(List.of(), List.of());

        when(tokenProvider.generateAccessToken(USERNAME, List.of(), List.of(), accessTtl))
                .thenReturn("access-empty");
        when(tokenProvider.generateRefreshToken(USERNAME, refreshTtl))
                .thenReturn("refresh-empty");
        when(tokenProvider.extractJti("refresh-empty"))
                .thenReturn("jti-empty");

        IssuedTokens tokens = tokenIssuer.issueTokens(USERNAME, empty);

        assertThat(tokens.accessToken()).isEqualTo("access-empty");
        assertThat(tokens.refreshToken()).isEqualTo("refresh-empty");
        assertThat(tokens.refreshJti()).isEqualTo("jti-empty");
    }
}
