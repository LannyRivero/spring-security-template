package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.exception.RefreshTokenReuseDetectedException;

import lombok.RequiredArgsConstructor;

/**
 * Application service responsible for orchestrating the refresh-token workflow.
 *
 * <p>
 * This class belongs to the pure <strong>application layer</strong> and
 * contains
 * no framework dependencies such as Spring, logging frameworks, MDC, or HTTP
 * concerns.
 * All cross-cutting responsibilities (audit, logging, correlation IDs, metrics)
 * must be handled by decorators (e.g., {@code AuthUseCaseLoggingDecorator}).
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Validate the refresh token via {@link TokenProvider}</li>
 * <li>Perform internal refresh-token validation (jti, expiration, replay
 * checks)</li>
 * <li>Apply rotation rules via {@link TokenRotationHandler}</li>
 * <li>Produce new token results using {@link TokenRefreshResultFactory}</li>
 * </ul>
 *
 * <h2>Non-responsibilities</h2>
 * <ul>
 * <li>No persistence</li>
 * <li>No logging</li>
 * <li>No exception mapping for HTTP</li>
 * <li>No Spring Security logic</li>
 * </ul>
 *
 * This strict separation keeps the refresh flow purely domain-oriented.
 */
@RequiredArgsConstructor
public class RefreshService {

    private final TokenProvider tokenProvider;
    private final RefreshTokenValidator validator;
    private final RefreshTokenStore refreshTokenStore;
    private final TokenRotationHandler rotationHandler;
    private final TokenRefreshResultFactory resultFactory;

    /**
     * Executes the refresh-token workflow for the provided {@link RefreshCommand}.
     *
     * <p>
     * Steps:
     * </p>
     * <ol>
     * <li>Extract and validate JWT claims from the refresh token</li>
     * <li>Perform domain-level refresh-token validation</li>
     * <li>Check for reuse detection (revoked token = attack)</li>
     * <li>Rotate the refresh token with family tracking</li>
     * <li>Return a {@link JwtResult} for the client</li>
     * </ol>
     *
     * @param cmd command object containing the original refresh token
     * @return a {@link JwtResult} containing new access or access+refresh tokens
     *
     * @throws IllegalArgumentException
     *                                  if the refresh token is invalid, expired,
     *                                  revoked, or malformed
     * @throws RefreshTokenReuseDetectedException
     *                                  if token reuse is detected (security breach)
     */
    public JwtResult refresh(RefreshCommand cmd) {

        return tokenProvider.validateAndGetClaims(cmd.refreshToken())
                .map(claims -> handleRefresh(claims, cmd))
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    /**
     * Applies validation, reuse detection, and rotation rules to the extracted JWT claims.
     *
     * <p>
     * <b>Reuse Detection Flow:</b>
     * <ol>
     * <li>Lookup token in database by JTI</li>
     * <li>If token is revoked → REUSE DETECTED → Revoke entire family</li>
     * <li>If token is valid → Revoke it (normal rotation)</li>
     * <li>Issue new token with same familyId</li>
     * </ol>
     * </p>
     *
     * @param claims validated JWT claims obtained from the provider
     * @param cmd    the refresh command containing the original refresh token
     * @return a new {@link JwtResult}
     * @throws RefreshTokenReuseDetectedException if token reuse is detected
     */
    private JwtResult handleRefresh(JwtClaimsDTO claims, RefreshCommand cmd) {
        // Validate token signature, expiration, JTI, and security rules
        validator.validate(claims);

        // Lookup token in database
        var tokenData = refreshTokenStore.findByJti(claims.jti())
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));

        // REUSE DETECTION: If token is already revoked, attacker is trying to reuse it
        if (tokenData.revoked()) {
            // Revoke entire family (all tokens in the rotation chain)
            refreshTokenStore.revokeFamily(tokenData.familyId());
            
            throw new RefreshTokenReuseDetectedException(
                    "Refresh token reuse detected for family: " + tokenData.familyId() + 
                    ". All tokens in this family have been revoked.");
        }

        // Check if token is expired
        if (tokenData.isExpired(java.time.Instant.now())) {
            throw new IllegalArgumentException("Refresh token expired");
        }

        // Normal flow: revoke current token and issue new one
        refreshTokenStore.revoke(claims.jti());

        // Determine if refresh token rotation is required
        if (rotationHandler.shouldRotate()) {
            // Rotate with family tracking (new token inherits same familyId)
            return rotationHandler.rotate(claims, tokenData.familyId());
        }

        // Otherwise return only a new access token, reusing the same refresh token
        return resultFactory.newAccessOnly(claims, cmd.refreshToken());
    }
}
