package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import com.lanny.spring_security_template.application.auth.policy.SessionPolicy;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;

import lombok.RequiredArgsConstructor;

/**
 * Pure application-layer session manager.
 *
 * Enforces:
 * - Session registration
 * - Concurrent session limits
 * - Automatic revocation of oldest sessions
 *
 * NO logging, NO auditing, NO Spring.
 * Cross-cutting concerns belong in the AuthUseCaseDecorator.
 */
@RequiredArgsConstructor
public class SessionManager {

    private final SessionRegistryGateway sessionRegistry;
    private final TokenBlacklistGateway blacklist;
    private final SessionPolicy policy;
    private final RefreshTokenStore refreshTokenStore;

    /**
     * Registers a new session and enforces max session concurrency.
     *
     * @param tokens issued token information
     */
    public void register(IssuedTokens tokens) {

        Objects.requireNonNull(tokens, "IssuedTokens must not be null");

        String username = tokens.username();
        String refreshJti = tokens.refreshJti();
        Instant refreshExp = tokens.refreshExp();

        // 1. Register the new session
        sessionRegistry.registerSession(username, refreshJti, refreshExp);

        int maxSessions = policy.maxSessionsPerUser();
        if (maxSessions <= 0) {
            // Unlimited sessions allowed
            return;
        }

        // 2. Fetch active sessions
        List<String> activeSessions = sessionRegistry.getActiveSessions(username);

        if (activeSessions.size() <= maxSessions) {
            return;
        }

        // 3. Calculate how many sessions to revoke
        int excess = activeSessions.size() - maxSessions;

        // 4. Revoke oldest sessions first
        for (int i = 0; i < excess; i++) {
            String jtiToRemove = activeSessions.get(i);

            // Revoke in blacklist
            blacklist.revoke(jtiToRemove, refreshExp);

            // Remove from registry
            sessionRegistry.removeSession(username, jtiToRemove);

            // Remove from persistent store
            refreshTokenStore.delete(jtiToRemove);
        }
    }
}
