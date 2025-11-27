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
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Ensure token audience matches the expected refresh audience.</li>
 * <li>Check that the token exists in the persistent store (not expired).</li>
 * <li>Verify that the token has not been revoked or reused.</li>
 * </ul>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 * <li>OWASP ASVS 2.7.3 – "Detect and invalidate reused refresh tokens".</li>
 * <li>OWASP ASVS 2.8.1 – "Ensure token revocation mechanisms are in
 * place".</li>
 * <li>OWASP ASVS 2.10.3 – "Log all session management events".</li>
 * </ul>
 *
 * <h2>Design Notes</h2>
 * <ul>
 * <li>This class belongs to the <strong>application</strong> layer.</li>
 * <li>It delegates storage and blacklist checks via outbound ports.</li>
 * <li>Does not depend on any security framework or persistence technology.</li>
 * </ul>
 */
@Component
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

        // Step 3: Validate not revoked or reused
        if (blacklist.isRevoked(claims.jti())) {
            throw new IllegalArgumentException("Refresh token revoked or re-used");
        }
    }
}
