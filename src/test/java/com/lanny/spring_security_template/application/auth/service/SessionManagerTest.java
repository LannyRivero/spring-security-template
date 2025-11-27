package com.lanny.spring_security_template.application.auth.service;

import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.policy.SessionPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.domain.time.ClockProvider;

/**
 * Unit tests for {@link SessionManager}.
 * Covers session registration, enforcement of limits, and token revocation.
 */
class SessionManagerTest {

    private SessionRegistryGateway sessionRegistry;
    private TokenBlacklistGateway blacklist;
    private SessionPolicy policy;
    private RefreshTokenStore refreshTokenStore;
    private ClockProvider clockProvider;
    private AuditEventPublisher auditEventPublisher;
    

    private SessionManager sessionManager;

    private static final String USERNAME = "lanny";

    private IssuedTokens tokens;

    @BeforeEach
    void setUp() {
        sessionRegistry = mock(SessionRegistryGateway.class);
        blacklist = mock(TokenBlacklistGateway.class);
        policy = mock(SessionPolicy.class);
        refreshTokenStore = mock(RefreshTokenStore.class);
        clockProvider = mock(ClockProvider.class);
        auditEventPublisher = mock(AuditEventPublisher.class);

        sessionManager = new SessionManager(sessionRegistry, blacklist, policy, refreshTokenStore, auditEventPublisher, clockProvider);

        tokens = new IssuedTokens(
                USERNAME,
                "access-token",
                "refresh-token",
                "refresh-jti",
                Instant.now(),
                Instant.now().plusSeconds(600),
                Instant.now().plusSeconds(3600),
                List.of("ROLE_USER"),
                List.of("profile:read"));
    }

    @Test
    @DisplayName(" should register session successfully when within limit")
    void testShouldRegisterSessionWithinLimit() {
        when(policy.maxSessionsPerUser()).thenReturn(3);
        when(sessionRegistry.getActiveSessions(USERNAME)).thenReturn(List.of("old1", "old2"));

        sessionManager.register(tokens);

        verify(sessionRegistry).registerSession(USERNAME, "refresh-jti", tokens.refreshExp());
        verifyNoInteractions(blacklist, refreshTokenStore);
    }

    @Test
    @DisplayName(" should not enforce limit when maxActiveSessions is 0 (unlimited)")
    void testShouldAllowUnlimitedSessions() {
        when(policy.maxSessionsPerUser()).thenReturn(0);

        sessionManager.register(tokens);

        verify(sessionRegistry).registerSession(USERNAME, "refresh-jti", tokens.refreshExp());
        verifyNoInteractions(blacklist, refreshTokenStore);
    }

    @Test
    @DisplayName(" should revoke and delete oldest sessions when exceeding max limit")
    void testShouldRevokeOldSessionsWhenExceedingLimit() {
        when(policy.maxSessionsPerUser()).thenReturn(2);
        when(sessionRegistry.getActiveSessions(USERNAME))
                .thenReturn(List.of("old1", "old2", "old3", "old4")); // 4 active sessions

        sessionManager.register(tokens);

        // Debe registrar nueva sesión
        verify(sessionRegistry).registerSession(USERNAME, "refresh-jti", tokens.refreshExp());

        // Exceso de 2 → eliminar los 2 más antiguos
        verify(blacklist).revoke("old1", tokens.refreshExp());
        verify(blacklist).revoke("old2", tokens.refreshExp());

        verify(sessionRegistry).removeSession(USERNAME, "old1");
        verify(sessionRegistry).removeSession(USERNAME, "old2");

        verify(refreshTokenStore).delete("old1");
        verify(refreshTokenStore).delete("old2");
    }
}
