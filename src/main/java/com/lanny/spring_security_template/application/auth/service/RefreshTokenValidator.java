package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;

import lombok.RequiredArgsConstructor;

/**
 * Core validator that enforces domain-level security rules
 * governing refresh tokens.
 *
 * <p>
 * This validator performs <strong>pure semantic validation</strong>
 * of refresh token claims, such as audience verification.
 * </p>
 *
 * <p>
 * <strong>Important:</strong>
 * This class intentionally performs <em>no persistence checks</em>
 * and <em>no token consumption</em>.
 * All stateful and concurrency-sensitive operations are delegated
 * to the refresh use case and persistence layer.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Validate refresh-token audience</li>
 * <li>Enforce refresh-token policy constraints</li>
 * </ul>
 *
 * <h2>Non-responsibilities</h2>
 * <ul>
 * <li>No database access</li>
 * <li>No blacklist checks</li>
 * <li>No token revocation or rotation</li>
 * </ul>
 */

@RequiredArgsConstructor
public class RefreshTokenValidator {

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
    }
}
