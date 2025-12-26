package com.lanny.spring_security_template.application.auth.service;


import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

import lombok.RequiredArgsConstructor;

import java.util.UUID;

/**
 * Centralized orchestrator for token issuance, persistence, and session
 * registration with family tracking support.
 *
 * <p>
 * This service acts as a façade to handle the full authentication lifecycle
 * after a successful login or registration. It encapsulates:
 * </p>
 *
 * <ul>
 * <li>Role and scope resolution for the user.</li>
 * <li>JWT token issuance via {@link TokenIssuer}.</li>
 * <li>Refresh token persistence via {@link RefreshTokenStore} with family tracking.</li>
 * <li>Session registration and enforcement via {@link SessionManager}.</li>
 * </ul>
 *
 * <h2>Family Tracking</h2>
 * <p>
 * Each new authentication session creates a new token family (unique familyId).
 * When tokens are rotated, they inherit the familyId from the previous token.
 * This enables reuse detection: if a revoked token is used, the entire family
 * is revoked.
 * </p>
 *
 * <h2>Design Notes</h2>
 * <ul>
 * <li>Stateless and deterministic — no side effects beyond ports.</li>
 * <li>Belongs to the <b>application layer</b> in Clean Architecture.</li>
 * <li>Ideal integration point for audit or metric recording in future
 * enhancements.</li>
 * </ul>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 * <li>OWASP ASVS 2.8.2 – Tokens should be securely stored and limited by
 * session.</li>
 * <li>OWASP ASVS 2.8.4 – Track issued tokens for revocation and auditing.</li>
 * <li>OWASP Refresh Token Rotation – Prevents token replay attacks.</li>
 * </ul>
 */
@RequiredArgsConstructor
public class TokenSessionCreator {

    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenIssuer tokenIssuer;
    private final SessionManager sessionManager;
    private final RefreshTokenStore refreshTokenStore;

    /**
     * Creates and persists a full token session for the given user with a new token family.
     *
     * <p>
     * Steps:
     * <ol>
     * <li>Generate a new familyId (UUID) for this authentication session.</li>
     * <li>Resolve the user's roles and scopes.</li>
     * <li>Issue access and refresh tokens.</li>
     * <li>Persist refresh token metadata with familyId (no previousTokenJti for initial token).</li>
     * <li>Register session and enforce session policy limits.</li>
     * </ol>
     * </p>
     *
     * @param username the authenticated user
     * @return {@link JwtResult} containing access and refresh tokens
     */
    public JwtResult create(String username) {
        // Step 1: Generate new family ID for this authentication session
        String familyId = UUID.randomUUID().toString();

        // Step 2: Resolve roles & scopes
        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // Step 3: Issue new token pair
        IssuedTokens tokens = tokenIssuer.issueTokens(username, rs);

        // Step 4: Persist refresh token metadata with family tracking
        // Initial token in family: previousTokenJti = null
        refreshTokenStore.save(
                username,
                tokens.refreshJti(),
                familyId,               // New family for this auth session
                null,                   // No previous token (first in family)
                tokens.issuedAt(),
                tokens.refreshExp()
        );

        // Step 5: Register new session
        sessionManager.register(tokens);

        return tokens.toJwtResult();
    }
}
