package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;

import lombok.RequiredArgsConstructor;

/**
 * Pure application-level refresh token validator.
 *
 * No Spring, no logging, no auditing, no MDC.
 * Cross-cutting concerns are handled by AuthUseCaseLoggingDecorator.
 */
@RequiredArgsConstructor
public class RefreshTokenValidator {

    private final RefreshTokenStore refreshTokenStore;
    private final TokenBlacklistGateway blacklist;
    private final RefreshTokenPolicy policy;

    /**
     * Performs all validation checks on the given JWT claims.
     *
     * @param claims the JWT claims extracted from a refresh token
     * @throws IllegalArgumentException if any validation rule fails
     */
    public void validate(JwtClaimsDTO claims) {

        // Step 1: Validate audience
        if (claims.aud() == null || !claims.aud().contains(policy.expectedRefreshAudience())) {
            throw new IllegalArgumentException("Invalid refresh token audience");
        }

        // Step 2: Validate existence in store
        if (!refreshTokenStore.exists(claims.jti())) {
            throw new IllegalArgumentException("Refresh token not found (revoked or expired)");
        }

        // Step 3: Validate that token is not blacklisted
        if (blacklist.isRevoked(claims.jti())) {
            throw new IllegalArgumentException("Refresh token revoked or re-used");
        }
    }
}

