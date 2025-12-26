package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;

import com.lanny.spring_security_template.application.auth.policy.RotationPolicy;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

import lombok.RequiredArgsConstructor;

/**
 * Application-layer service responsible for handling secure refresh-token
 * rotation.
 *
 * <p>
 * Token rotation is the core mechanism that prevents:
 * </p>
 * <ul>
 * <li>Refresh token replay attacks</li>
 * <li>Session fixation</li>
 * <li>Long-lived session hijacking</li>
 * </ul>
 *
 * <p>
 * This class performs rotation strictly according to the rules enforced by
 * {@link RotationPolicy}, and relies on purely application-level ports:
 * </p>
 * <ul>
 * <li>{@link RoleProvider} — loads user roles needed to re-issue tokens</li>
 * <li>{@link ScopePolicy} — resolves effective scopes for the user</li>
 * <li>{@link TokenIssuer} — generates new access and refresh tokens</li>
 * <li>{@link RefreshTokenStore} — persists token metadata for replay
 * protection</li>
 * <li>{@link SessionRegistryGateway} — enforces session lifecycle tracking</li>
 * <li>{@link TokenBlacklistGateway} — immediately revokes the old refresh
 * token</li>
 * </ul>
 *
 * <p>
 * <strong>NOTE:</strong> This class contains no logging, auditing, MDC, or
 * Spring
 * dependencies. All cross-cutting concerns are delegated to decorators such as
 * {@code AuthUseCaseLoggingDecorator}.
 * </p>
 */
@RequiredArgsConstructor
public class TokenRotationHandler {

    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final SessionRegistryGateway sessionRegistry;
    private final TokenBlacklistGateway blacklist;
    private final RotationPolicy rotationPolicy;

    /**
     * Indicates whether refresh-token rotation is globally enabled.
     *
     * <p>
     * This allows different deployment environments (e.g., local, staging,
     * production) to toggle rotation behavior without changing application code.
     * </p>
     *
     * @return {@code true} if rotation should occur, {@code false} otherwise
     */
    public boolean shouldRotate() {
        return rotationPolicy.isRotationEnabled();
    }

    /**
     * Performs secure refresh-token rotation using a five-step process:
     *
     * <ol>
     * <li><strong>Resolve user roles & scopes</strong> used in the new JWT.</li>
     * <li><strong>Revoke old refresh token</strong> via blacklist to prevent
     * reuse.</li>
     * <li><strong>Delete old token metadata</strong> from persistent storage.</li>
     * <li><strong>Issue new access + refresh tokens</strong> with updated
     * expiry.</li>
     * <li><strong>Persist new session</strong> in the session registry & token
     * store.</li>
     * </ol>
     *
     * <p>
     * This ensures:
     * </p>
     * <ul>
     * <li>Replay protection — old refresh tokens cannot be reused.</li>
     * <li>Session continuity — a new session replaces the old one.</li>
     * <li>Security invariants — metadata and lifecycle remain synchronized.</li>
     * </ul>
     *
    /**
     * Performs secure refresh-token rotation with family tracking using a six-step process:
     *
     * <ol>
     * <li><strong>Resolve user roles & scopes</strong> used in the new JWT.</li>
     * <li><strong>Revoke old refresh token</strong> via blacklist to prevent reuse.</li>
     * <li><strong>Mark old token as revoked</strong> in persistent storage.</li>
     * <li><strong>Issue new access + refresh tokens</strong> with same familyId.</li>
     * <li><strong>Persist new token</strong> with link to previous token (chain tracking).</li>
     * <li><strong>Update session</strong> in the session registry.</li>
     * </ol>
     *
     * <p>
     * This ensures:
     * </p>
     * <ul>
     * <li>Replay protection — old refresh tokens cannot be reused.</li>
     * <li>Family tracking — all rotated tokens share the same familyId.</li>
     * <li>Reuse detection — attempting to use a revoked token triggers family revocation.</li>
     * <li>Audit trail — token chain preserved via previousTokenJti links.</li>
     * </ul>
     *
     * @param claims   JWT claims extracted from the old refresh token
     * @param familyId family identifier to maintain across rotation
     * @return {@link JwtResult} containing the newly issued access & refresh tokens
     * @throws IllegalArgumentException if any step of the rotation fails
     */
    public JwtResult rotate(JwtClaimsDTO claims, String familyId) {

        String username = claims.sub();
        String oldJti = claims.jti();

        // 1. Resolve roles + scopes for token issuance
        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // 2. Revoke the old refresh token in blacklist (fast revocation)
        blacklist.revoke(oldJti, Instant.ofEpochSecond(claims.exp()));

        // 3. Mark old token as revoked in database (for reuse detection)
        refreshTokenStore.revoke(oldJti);
        sessionRegistry.removeSession(username, oldJti);

        // 4. Issue new access & refresh pair
        IssuedTokens tokens = tokenIssuer.issueTokens(username, rs);

        // 5. Persist new token with family tracking
        // - Same familyId as the rotated token
        // - Link to previous token via previousTokenJti
        refreshTokenStore.save(
                username,
                tokens.refreshJti(),
                familyId,               // Inherit family from rotated token
                oldJti,                 // Link to previous token in chain
                tokens.issuedAt(),
                tokens.refreshExp()
        );

        // 6. Update session registry with new JTI
        sessionRegistry.registerSession(username, tokens.refreshJti(), tokens.refreshExp());

        return tokens.toJwtResult();
    }
}
