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
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

/**
 * Unit tests for {@link TokenSessionCreator}.
 * Verifies that tokens are issued, persisted and sessions registered.
 */
class TokenSessionCreatorTest {

        private RoleProvider roleProvider;
        private ScopePolicy scopePolicy;
        private TokenIssuer tokenIssuer;
        private SessionManager sessionManager;
        private RefreshTokenStore refreshTokenStore;

        private TokenSessionCreator creator;

        private static final String USERNAME = "lanny";
        private static final String REFRESH_JTI = "rjti-001";

        private IssuedTokens issuedTokens;

        @BeforeEach
        void setUp() {
                roleProvider = mock(RoleProvider.class);
                scopePolicy = mock(ScopePolicy.class);
                tokenIssuer = mock(TokenIssuer.class);
                sessionManager = mock(SessionManager.class);
                refreshTokenStore = mock(RefreshTokenStore.class);

                creator = new TokenSessionCreator(
                                roleProvider, scopePolicy, tokenIssuer, sessionManager, refreshTokenStore);

                issuedTokens = new IssuedTokens(
                                USERNAME,
                                "access-token",
                                "refresh-token",
                                REFRESH_JTI,
                                Instant.now(),
                                Instant.now().plusSeconds(900),
                                Instant.now().plusSeconds(3600),
                                List.of("ROLE_USER"),
                                List.of("profile:read"));
        }

        @Test
        @DisplayName(" should issue tokens, save refresh token and register session")
        void testShouldCreateSessionAndReturnJwtResult() {
                // Arrange
                when(roleProvider.resolveRoles(USERNAME))
                                .thenReturn(Set.of(new Role("ROLE_USER", Set.of(new Scope("profile:read")))));
                when(scopePolicy.resolveScopes(any())).thenReturn(Set.of(new Scope("profile:read")));
                when(tokenIssuer.issueTokens(eq(USERNAME), any(RoleScopeResult.class)))
                                .thenReturn(issuedTokens);

                // Act
                JwtResult result = creator.create(USERNAME);

                // Assert
                assertThat(result).isNotNull();
                assertThat(result.accessToken()).isEqualTo("access-token");
                assertThat(result.refreshToken()).isEqualTo("refresh-token");

                verify(refreshTokenStore).save(eq(USERNAME), eq(REFRESH_JTI), any(), any());
                verify(sessionManager).register(eq(issuedTokens));
                verify(tokenIssuer).issueTokens(eq(USERNAME), any(RoleScopeResult.class));

                verifyNoMoreInteractions(refreshTokenStore, sessionManager, tokenIssuer);
        }

        @Test
        @DisplayName(" should propagate any exception during token issuing")
        void testShouldPropagateIfIssuerFails() {
                when(roleProvider.resolveRoles(USERNAME))
                                .thenReturn(Set.of(new Role("ROLE_USER", Set.of())));
                when(scopePolicy.resolveScopes(any())).thenReturn(Set.of());
                when(tokenIssuer.issueTokens(eq(USERNAME), any())).thenThrow(new RuntimeException("Issuer error"));

                assertThatThrownBy(() -> creator.create(USERNAME))
                                .isInstanceOf(RuntimeException.class)
                                .hasMessage("Issuer error");

                verify(refreshTokenStore, never()).save(any(), any(), any(), any());
                verify(sessionManager, never()).register(any());
        }

        @Test
        @DisplayName(" should resolve roles and scopes before token issuance")
        void testShouldResolveRolesAndScopesBeforeIssuing() {
                when(roleProvider.resolveRoles(USERNAME))
                                .thenReturn(Set.of(new Role("ROLE_ADMIN", Set.of(new Scope("manage:users")))));
                when(scopePolicy.resolveScopes(any())).thenReturn(Set.of(new Scope("manage:users")));
                when(tokenIssuer.issueTokens(eq(USERNAME), any(RoleScopeResult.class)))
                                .thenReturn(issuedTokens);

                creator.create(USERNAME);

                verify(roleProvider).resolveRoles(USERNAME);
                verify(scopePolicy).resolveScopes(any());
        }

}
