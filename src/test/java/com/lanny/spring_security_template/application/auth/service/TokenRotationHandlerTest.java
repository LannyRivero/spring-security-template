package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceImpl;

/**
 * Unit tests for {@link TokenRotationHandler}.
 * Verifies rotation flow, blacklist and persistence.
 */
class TokenRotationHandlerTest {

    private RoleProvider roleProvider;
    private ScopePolicy scopePolicy;
    private TokenIssuer tokenIssuer;
    private RefreshTokenStore refreshTokenStore;
    private SessionRegistryGateway sessionRegistry;
    private TokenBlacklistGateway blacklist;
    private SecurityJwtProperties props;
    private AuthMetricsServiceImpl metrics;
    private TokenRotationHandler handler;

    private static final String USERNAME = "lanny";
    private static final String OLD_JTI = "old-jti-123";
    private static final String NEW_JTI = "new-jti-456";

    private IssuedTokens issuedTokens;
    private JwtClaimsDTO claims;

    @BeforeEach
    void setUp() {
        roleProvider = mock(RoleProvider.class);
        scopePolicy = mock(ScopePolicy.class);
        tokenIssuer = mock(TokenIssuer.class);
        refreshTokenStore = mock(RefreshTokenStore.class);
        sessionRegistry = mock(SessionRegistryGateway.class);
        blacklist = mock(TokenBlacklistGateway.class);
        props = mock(SecurityJwtProperties.class);
        metrics = mock(AuthMetricsServiceImpl.class);

        handler = new TokenRotationHandler(
                roleProvider, scopePolicy, tokenIssuer,
                refreshTokenStore, sessionRegistry, blacklist,
                props, metrics);

        // Datos base
        claims = new JwtClaimsDTO(
                USERNAME,
                OLD_JTI,
                List.of("auth-service"),
                Instant.now().getEpochSecond(),
                Instant.now().getEpochSecond(),
                Instant.now().plusSeconds(3600).getEpochSecond(),
                List.of("ROLE_USER"),
                List.of("profile:read"));

        issuedTokens = new IssuedTokens(
                USERNAME,
                "access-new",
                "refresh-new",
                NEW_JTI,
                Instant.now(),
                Instant.now().plusSeconds(900),
                Instant.now().plusSeconds(3600),
                List.of("ROLE_USER"),
                List.of("profile:read"));
    }

    @Test
    @DisplayName(" should perform full rotation and persist new session")
    void testShouldRotateAndPersist() {
        // Arrange
        when(roleProvider.resolveRoles(USERNAME))
                .thenReturn(Set.of(new com.lanny.spring_security_template.domain.model.Role("ROLE_USER", Set.of())));
        when(scopePolicy.resolveScopes(any())).thenReturn(Set.of(
                new com.lanny.spring_security_template.domain.model.Scope("profile:read")));
        when(tokenIssuer.issueTokens(eq(USERNAME), any(RoleScopeResult.class)))
                .thenReturn(issuedTokens);

        // Act
        JwtResult result = handler.rotate(claims);

        // Assert
        assertThat(result.accessToken()).isEqualTo("access-new");
        assertThat(result.refreshToken()).isEqualTo("refresh-new");

        // Verificar orden lógico de acciones
        verify(blacklist).revoke(eq(OLD_JTI), any());
        verify(refreshTokenStore).delete(OLD_JTI);
        verify(sessionRegistry).removeSession(USERNAME, OLD_JTI);

        verify(tokenIssuer).issueTokens(eq(USERNAME), any());
        verify(refreshTokenStore).save(eq(USERNAME), eq(NEW_JTI), any(), any());
        verify(sessionRegistry).registerSession(eq(USERNAME), eq(NEW_JTI), any());
        verify(metrics).recordTokenRefresh();

        verifyNoMoreInteractions(blacklist, refreshTokenStore, sessionRegistry, tokenIssuer);
    }

    @Test
    @DisplayName(" should return true when rotation enabled in properties")
    void testShouldRotateWhenEnabled() {
        when(props.rotateRefreshTokens()).thenReturn(true);
        assertThat(handler.shouldRotate()).isTrue();
    }

    @Test
    @DisplayName(" should return false when rotation disabled in properties")
    void testShouldNotRotateWhenDisabled() {
        when(props.rotateRefreshTokens()).thenReturn(false);
        assertThat(handler.shouldRotate()).isFalse();
    }
}
