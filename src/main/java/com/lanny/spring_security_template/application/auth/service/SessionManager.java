package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;
import java.util.List;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.SessionPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

/**
 *  Manages user sessions according to the configured {@link SessionPolicy}.
 *
 * <p>
 * This component enforces session registration and concurrency limits:
 * <ul>
 *   <li>Registers each new refresh token as an active session.</li>
 *   <li>Revokes oldest sessions when the max session count is exceeded.</li>
 *   <li>Publishes audit events for registration and revocation actions.</li>
 * </ul>
 * </p>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 *   <li>OWASP ASVS 2.8.3 – “Limit concurrent sessions per user.”</li>
 *   <li>OWASP ASVS 2.8.4 – “Revoke oldest sessions when limits exceeded.”</li>
 *   <li>OWASP ASVS 2.10.3 – “Log all session management events.”</li>
 * </ul>
 */
@Component
@RequiredArgsConstructor
public class SessionManager {

    private final SessionRegistryGateway sessionRegistry;
    private final TokenBlacklistGateway blacklist;
    private final SessionPolicy policy;
    private final RefreshTokenStore refreshTokenStore;
    private final AuditEventPublisher auditEventPublisher;
    private final ClockProvider clockProvider;

    /**
     * Registers a new user session and enforces concurrency limits.
     *
     * @param tokens newly issued access/refresh token pair
     */
    public void register(IssuedTokens tokens) {
        String username = tokens.username();
        Instant now = clockProvider.now();

        //  Step 1: Register new session
        sessionRegistry.registerSession(username, tokens.refreshJti(), tokens.refreshExp());
        auditEventPublisher.publishAuthEvent(
                "SESSION_REGISTERED",
                username,
                now,
                "New session registered for refresh token JTI=" + tokens.refreshJti()
        );

        int maxSessions = policy.maxSessionsPerUser();

        //  Step 2: If unlimited sessions are allowed, exit early
        if (maxSessions <= 0) return;

        List<String> sessions = sessionRegistry.getActiveSessions(username);

        //  Step 3: Enforce session limit
        if (sessions.size() <= maxSessions) return;

        int excess = sessions.size() - maxSessions;

        //  Step 4: Revoke the oldest sessions first
        for (int i = 0; i < excess; i++) {
            String jtiToRemove = sessions.get(i);

            // 1. Revoke from blacklist
            blacklist.revoke(jtiToRemove, tokens.refreshExp());

            // 2. Remove from session registry
            sessionRegistry.removeSession(username, jtiToRemove);

            // 3. Delete from persistent refresh store
            refreshTokenStore.delete(jtiToRemove);

            // 4. Publish audit event
            auditEventPublisher.publishAuthEvent(
                    "SESSION_REVOKED",
                    username,
                    now,
                    "Revoked session with refresh JTI=" + jtiToRemove + " due to session limit exceeded"
            );
        }
    }
}

