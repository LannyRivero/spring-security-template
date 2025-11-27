package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.policy.TokenPolicyProperties;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link TokenRefreshResultFactory}.
 * Ensures access token regeneration without refresh rotation.
 */
class TokenRefreshResultFactoryTest {

        private RoleProvider roleProvider;
        private ScopePolicy scopePolicy;
        private TokenProvider tokenProvider;
        private ClockProvider clockProvider;
        private TokenPolicyProperties tokenPolicy;

        private TokenRefreshResultFactory factory;

        private static final String USERNAME = "lanny";
        private static final String REFRESH_TOKEN = "refresh-abc";
        private static final String NEW_ACCESS = "access-xyz";

        private final Instant now = Instant.parse("2030-01-01T00:00:00Z");
        private final Duration accessTtl = Duration.ofMinutes(15);

        @BeforeEach
        void setUp() {
                roleProvider = mock(RoleProvider.class);
                scopePolicy = mock(ScopePolicy.class);
                tokenProvider = mock(TokenProvider.class);
                clockProvider = mock(ClockProvider.class);
                tokenPolicy = mock(TokenPolicyProperties.class);

                factory = new TokenRefreshResultFactory(roleProvider, scopePolicy, tokenProvider, clockProvider,
                                tokenPolicy);

                when(clockProvider.now()).thenReturn(now);
                when(tokenPolicy.accessTokenTtl()).thenReturn(accessTtl);
        }

        @Test
        @DisplayName(" should create new access token using existing refresh token")
        void testShouldCreateNewAccessToken() {
                // Arrange
                JwtClaimsDTO claims = new JwtClaimsDTO(
                                USERNAME,
                                "jti-123",
                                List.of("auth-service"),
                                now.getEpochSecond(),
                                now.getEpochSecond(),
                                now.plusSeconds(3600).getEpochSecond(),
                                List.of("ROLE_USER"),
                                List.of("profile:read"));

                // Mock role and scope resolution
                when(roleProvider.resolveRoles(USERNAME))
                                .thenReturn(Set.of(new com.lanny.spring_security_template.domain.model.Role("ROLE_USER",
                                                Set.of())));
                when(scopePolicy.resolveScopes(any())).thenReturn(Set.of(
                                new com.lanny.spring_security_template.domain.model.Scope("profile:read")));

                when(tokenProvider.generateAccessToken(
                                eq(USERNAME),
                                anyList(),
                                anyList(),
                                eq(accessTtl))).thenReturn(NEW_ACCESS);

                // Act
                JwtResult result = factory.newAccessOnly(claims, REFRESH_TOKEN);

                // Assert
                assertThat(result.accessToken()).isEqualTo(NEW_ACCESS);
                assertThat(result.refreshToken()).isEqualTo(REFRESH_TOKEN);

                verify(tokenProvider).generateAccessToken(
                                eq(USERNAME),
                                argThat(r -> r.contains("ROLE_USER")),
                                argThat(s -> s.contains("profile:read")),
                                eq(accessTtl));
        }

        @Test
        @DisplayName(" should handle users with no roles or scopes gracefully")
        void testShouldHandleEmptyRolesAndScopes() {
                JwtClaimsDTO claims = new JwtClaimsDTO(
                                USERNAME,
                                "jti-000",
                                List.of("auth-service"),
                                now.getEpochSecond(),
                                now.getEpochSecond(),
                                now.plusSeconds(3600).getEpochSecond(),
                                List.of(),
                                List.of());

                when(roleProvider.resolveRoles(USERNAME)).thenReturn(Set.of());
                when(scopePolicy.resolveScopes(any())).thenReturn(Set.of());
                when(tokenProvider.generateAccessToken(USERNAME, List.of(), List.of(), accessTtl))
                                .thenReturn("access-empty");

                JwtResult result = factory.newAccessOnly(claims, REFRESH_TOKEN);

                assertThat(result.accessToken()).isEqualTo("access-empty");
                assertThat(result.refreshToken()).isEqualTo(REFRESH_TOKEN);
                verify(tokenProvider).generateAccessToken(USERNAME, List.of(), List.of(), accessTtl);
        }

        @Test
        @DisplayName(" should assign expiration correctly based on policy TTL")
        void testShouldAssignCorrectExpiration() {
                JwtClaimsDTO claims = new JwtClaimsDTO(
                                USERNAME, "jti-456", List.of("auth-service"),
                                now.getEpochSecond(), now.getEpochSecond(),
                                now.plusSeconds(3600).getEpochSecond(),
                                List.of(), List.of());

                when(roleProvider.resolveRoles(USERNAME)).thenReturn(Set.of());
                when(scopePolicy.resolveScopes(any())).thenReturn(Set.of());
                when(tokenProvider.generateAccessToken(USERNAME, List.of(), List.of(), accessTtl))
                                .thenReturn("access-time");

                JwtResult result = factory.newAccessOnly(claims, REFRESH_TOKEN);

                assertThat(result.expiresAt()).isEqualTo(now.plus(accessTtl));
        }

}
