package com.lanny.spring_security_template.application.auth.service;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;

import lombok.RequiredArgsConstructor;

/**
 * Validates the integrity, audience, and revocation status
 * of a refresh token before it is used for renewal.
 */
@Component
@RequiredArgsConstructor
public class RefreshTokenValidator {

    private final RefreshTokenStore refreshTokenStore;
    private final TokenBlacklistGateway blacklist;
    private final RefreshTokenPolicy policy;

    /**
     * Perform all validation checks on the given JWT claims.
     *
     * @throws IllegalArgumentException if any validation rule fails
     */
    public void validate(JwtClaimsDTO claims) {
        // 1️Validate audience
        if (claims.aud() == null || !claims.aud().contains(policy.expectedRefreshAudience())) {
            throw new IllegalArgumentException("Invalid refresh token audience");
        }

        // 2️ Validate existence in store
        if (!refreshTokenStore.exists(claims.jti())) {
            throw new IllegalArgumentException("Refresh token not found (revoked or expired)");
        }

        // 3️ Validate not revoked
        if (blacklist.isRevoked(claims.jti())) {
            throw new IllegalArgumentException("Refresh token revoked or re-used");
        }
    }
}
