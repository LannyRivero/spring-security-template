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
     * <li>Either rotate the refresh token or reuse it</li>
     * <li>Return a {@link JwtResult} for the client</li>
     * </ol>
     *
     * @param cmd command object containing the original refresh token
     * @return a {@link JwtResult} containing new access or access+refresh tokens
     *
     * @throws IllegalArgumentException
     *                                  if the refresh token is invalid, expired,
     *                                  revoked, or malformed
     */
    public JwtResult refresh(RefreshCommand cmd) {

        return tokenProvider.validateAndGetClaims(cmd.refreshToken())
                .map(claims -> handleRefresh(claims, cmd))
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    /**
     * Applies validation and rotation rules to the extracted JWT claims.
     *
     * @param claims validated JWT claims obtained from the provider
     * @param cmd    the refresh command containing the original refresh token
     * @return a new {@link JwtResult}
     */
    private JwtResult handleRefresh(JwtClaimsDTO claims, RefreshCommand cmd) {
        // Validate token signature, expiration, JTI, and security rules
        validator.validate(claims);

        boolean consumed = refreshTokenStore.consume(claims.jti());

        if (!consumed) {
            throw new RefreshTokenReuseDetectedException("Refresh token reuse detected");

        }

        // Determine if refresh token rotation is required
        if (rotationHandler.shouldRotate()) {
            return rotationHandler.rotate(claims);
        }

        // Otherwise return only a new access token, reusing the same refresh token
        return resultFactory.newAccessOnly(claims, cmd.refreshToken());
    }
}
