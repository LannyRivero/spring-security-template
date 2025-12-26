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
 * Application-layer session manager enforcing server-side session lifecycle
 * rules
 * for refresh tokens.
 *
 * <p>
 * Responsibilities:
 * </p>
 * <ul>
 * <li><strong>Session Registration</strong> — Every newly issued refresh token
 * is stored with its expiration metadata for later validation.</li>
 *
 * <li><strong>Concurrent Session Limiting</strong> — Enforces the maximum
 * number
 * of allowed concurrent sessions per user, as configured by
 * {@link SessionPolicy}.</li>
 *
 * <li><strong>Automatic Session Revocation</strong> — If a user exceeds their
 * session limit, the oldest refresh tokens are revoked, removed from the
 * registry, and deleted from persistent storage.</li>
 * </ul>
 *
 * <p>
 * This component is intentionally <strong>pure application logic</strong>:
 * no logging, no Spring annotations, no MDC, no auditing.
 * Cross-cutting concerns (audit events, logging, metrics) belong in
 * higher-level decorators such as {@code AuthUseCaseLoggingDecorator}.
 * </p>
 *
 * <p>
 * Design principles followed:
 * </p>
 * <ul>
 * <li>Single Responsibility — session lifecycle enforcement only.</li>
 * <li>Infrastructure-agnostic — depends only on gateway interfaces.</li>
 * <li>Deterministic behavior — oldest sessions always revoked first.</li>
 * </ul>
 */
@RequiredArgsConstructor
public class SessionManager {

    private final SessionRegistryGateway sessionRegistry;
    private final TokenBlacklistGateway blacklist;
    private final SessionPolicy policy;
    private final RefreshTokenStore refreshTokenStore;

    /**
     * Registers a newly issued refresh token and enforces the maximum
     * number of concurrent sessions for a given user.
     *
     * <p>
     * The algorithm:
     * </p>
     *
     * <ol>
     * <li>Register the new refresh-token session in the session registry.</li>
     * <li>If concurrent-session limiting is disabled
     * (<code>maxSessionsPerUser <= 0</code>),
     * return immediately.</li>
     * <li>Retrieve all active sessions for the user.</li>
     * <li>If the number of sessions exceeds the configured limit, revoke the
     * oldest sessions first using the following steps:
     * <ul>
     * <li>Blacklist the refresh token (prevents reuse).</li>
     * <li>Remove its entry from the session registry.</li>
     * <li>Delete its record from persistent refresh-token storage.</li>
     * </ul>
     * </li>
     * </ol>
     *
     * @param tokens metadata about the newly issued access + refresh token pair
     * @throws NullPointerException if the given {@code IssuedTokens} is
     *                              {@code null}
     */
    public void register(IssuedTokens tokens) {

        Objects.requireNonNull(tokens, "IssuedTokens must not be null");

        String username = tokens.username();
        String refreshJti = tokens.refreshJti();
        Instant refreshExp = tokens.refreshExp();

        // 1. Register new session
        sessionRegistry.registerSession(username, refreshJti, refreshExp);

        int maxSessions = policy.maxSessionsPerUser();
        if (maxSessions <= 0) {
            // Unlimited sessions allowed
            return;
        }

        // 2. Get current active sessions
        List<String> activeSessions = sessionRegistry.getActiveSessions(username);

        if (activeSessions.size() <= maxSessions) {
            return;
        }

        // 3. Determine how many sessions must be revoked
        int excess = activeSessions.size() - maxSessions;

        // 4. Revoke the oldest sessions deterministically
        for (int i = 0; i < excess; i++) {
            String jtiToRemove = activeSessions.get(i);

            // Revoke in blacklist
            blacklist.revoke(jtiToRemove, refreshExp);

            // Atomicall consume rfresh token metadata
            refreshTokenStore.revoke(jtiToRemove);

            // Remove from session registry
            sessionRegistry.removeSession(username, jtiToRemove);
        }
    }
}
