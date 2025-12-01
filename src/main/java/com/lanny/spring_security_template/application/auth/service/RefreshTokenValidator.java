package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;

import lombok.RequiredArgsConstructor;

/**
 * Core validator that enforces the security rules governing refresh tokens.
 * 
 * <p>
 * Performs audience verification, existence validation in the token store, and
 * blacklist checks. Any failure results in {@link IllegalArgumentException}.
 * </p>
 */
@RequiredArgsConstructor
public class RefreshTokenValidator {

    private final RefreshTokenStore refreshTokenStore;
    private final TokenBlacklistGateway blacklist;
    private final RefreshTokenPolicy policy;

    /**
     * Validates the given refresh-token claims against all security policies.
     *
     * @param claims the decoded JWT claims obtained from a refresh token
     * @throws IllegalArgumentException if any validation rule is violated
     */
    public void validate(JwtClaimsDTO claims) {

        // 1 — Validate audience
        if (claims.aud() == null || !claims.aud().contains(policy.expectedRefreshAudience())) {
            throw new IllegalArgumentException("Invalid refresh token audience");
        }

        // 2 — Validate token exists in store
        if (!refreshTokenStore.exists(claims.jti())) {
            throw new IllegalArgumentException("Refresh token not found (revoked or expired)");
        }

        // 3 — Validate token not revoked (blacklist)
        if (blacklist.isRevoked(claims.jti())) {
            throw new IllegalArgumentException("Refresh token revoked or re-used");
        }
    }
}
