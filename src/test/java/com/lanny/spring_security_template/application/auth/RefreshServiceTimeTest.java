package com.lanny.spring_security_template.application.auth;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.service.RefreshService;
import com.lanny.spring_security_template.application.auth.service.RoleScopeResult;
import com.lanny.spring_security_template.application.auth.service.TokenIssuer;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceImpl;
import com.lanny.spring_security_template.testsupport.time.MutableClockProvider;

class RefreshServiceTimeTest {

    @Test
    @DisplayName("Refreshing token should succeed if refresh token has NOT expired")
    void refreshShouldSucceedBeforeExpiration() {
        // Arrange
        Instant start = Instant.parse("2035-01-01T00:00:00Z");
        ClockProvider clock = new MutableClockProvider(start);

        TokenProvider tokenProvider = mock(TokenProvider.class);
        RoleProvider roleProvider = mock(RoleProvider.class);
        ScopePolicy scopePolicy = mock(ScopePolicy.class);
        RefreshTokenStore refreshTokenStore = mock(RefreshTokenStore.class);
        SessionRegistryGateway sessionRegistry = mock(SessionRegistryGateway.class);
        TokenBlacklistGateway blacklist = mock(TokenBlacklistGateway.class);
        SecurityJwtProperties props = mock(SecurityJwtProperties.class);
        TokenIssuer tokenIssuer = mock(TokenIssuer.class);
        AuthMetricsServiceImpl metrics = mock(AuthMetricsServiceImpl.class);

        // Configuración mínima necesaria para el test
        when(props.refreshAudience()).thenReturn("auth-service");
        when(props.accessTtl()).thenReturn(Duration.ofMinutes(15));
        when(props.rotateRefreshTokens()).thenReturn(false);

        String refresh = "valid-refresh-token";

        // Simulamos claims válidos
        JwtClaimsDTO claims = new JwtClaimsDTO(
                "alice",
                "jti-123",
                List.of("auth-service"),
                1000L,
                1000L,
                2000L,
                List.of("ROLE_USER"),
                List.of("profile:read"));

        when(tokenProvider.validateAndGetClaims(refresh)).thenReturn(java.util.Optional.of(claims));
        when(refreshTokenStore.exists("jti-123")).thenReturn(true);
        when(blacklist.isRevoked("jti-123")).thenReturn(false);

        // Para que RoleScopeResolver no falle: roles + scopes reconstr
        RoleScopeResult rs = new RoleScopeResult(
                List.of("ROLE_USER"),
                List.of("profile:read"));
        // Como RoleScopeResolver es estático, puedes:
        // - usar una versión real sobre tus mocks
        // - o si eso te complica, aislarlo en otro test.
        // Para mantenerlo simple, asumimos que funciona y que el
        // tokenProvider.generateAccessToken se usa.

        when(tokenProvider.generateAccessToken(
                eq("alice"),
                eq(rs.roleNames()),
                eq(rs.scopeNames()),
                any())).thenReturn("new-access-token");

        RefreshService service = new RefreshService(
                tokenProvider,
                roleProvider,
                scopePolicy,
                refreshTokenStore,
                sessionRegistry,
                blacklist,
                props,
                clock,
                tokenIssuer,
                metrics);

        // Act
        JwtResult result = service.refresh(new RefreshCommand(refresh));

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.accessToken()).isEqualTo("new-access-token");
        assertThat(result.refreshToken()).isEqualTo(refresh);
    }
}
