package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.policy.SessionPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
@RequiredArgsConstructor
public class SessionManager {

    private final SessionRegistryGateway sessionRegistry;
    private final TokenBlacklistGateway blacklist;
    private final SessionPolicy policy;
    private final RefreshTokenStore refreshTokenStore;
    private final AuditEventPublisher auditEventPublisher;
    private final ClockProvider clockProvider;

    public void register(IssuedTokens tokens) {

        String username = tokens.username();
        Instant now = clockProvider.now();

        // Registrar nueva sesión
        sessionRegistry.registerSession(
                username,
                tokens.refreshJti(),
                tokens.refreshExp());
        auditEventPublisher.publishAuthEvent(
            "SESSION_REGISTERED",
            username,
            now,
            "New session registered for refresh token JTI=" + tokens.refreshJti()
        );

        int maxSessions = policy.maxSessionsPerUser();

        if (maxSessions <= 0) {
            return; // sin límite
        }

        List<String> sessions = sessionRegistry.getActiveSessions(username);

        if (sessions.size() <= maxSessions) {
            return;
        }

        int excess = sessions.size() - maxSessions;

        for (int i = 0; i < excess; i++) {
            String jtiToRemove = sessions.get(i);

            // Revocamos el refresh antiguo
            blacklist.revoke(jtiToRemove, tokens.refreshExp());

            // Eliminamos del registry
            sessionRegistry.removeSession(username, jtiToRemove);

            // Eliminamos de BD
            refreshTokenStore.delete(jtiToRemove);

            auditEventPublisher.publishAuthEvent(
            "SESSION_REVOKED",
                username,
                now,
                "Revoked session with refresh JTI=" + jtiToRemove + " due to aession limit exceeded"
            );
        }
    }
}
