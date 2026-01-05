package com.lanny.spring_security_template.application.auth.service;

import java.time.Duration;
import java.time.Instant;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;
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
 * This class belongs to the <strong>application layer</strong> and contains
 * no framework, logging, MDC, or HTTP concerns.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 *   <li>Cryptographic validation via {@link TokenProvider}</li>
 *   <li>Atomic refresh token consumption (anti-replay)</li>
 *   <li>Family-based rotation with reuse detection</li>
 *   <li>Fail-fast behavior on compromised tokens</li>
 * </ul>
 */
@RequiredArgsConstructor
public class RefreshService {

    private final TokenProvider tokenProvider;
    private final RefreshTokenValidator validator;
     private final RefreshTokenConsumptionPort refreshTokenConsumption;
    private final RefreshTokenStore refreshTokenStore;
    private final TokenRotationHandler rotationHandler;
    private final TokenRefreshResultFactory resultFactory;
   

    /**
     * Executes the refresh-token workflow for the provided {@link RefreshCommand}.
     *
     * @param cmd command containing the refresh token
     * @return new access or access+refresh tokens
     */
    public JwtResult refresh(RefreshCommand cmd) {

        return tokenProvider.validateAndGetClaims(cmd.refreshToken())
                .map(claims -> handleRefresh(claims, cmd))
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    /**
     * Core refresh-token handling logic.
     *
     * <p>
     * Execution order is SECURITY-CRITICAL and must not be changed.
     * </p>
     */
    private JwtResult handleRefresh(JwtClaimsDTO claims, RefreshCommand cmd) {

        // -----------------------------------------------------------------
        // 1. Domain-level validation (iss, aud, exp, token_use, jti, etc.)
        // -----------------------------------------------------------------
        validator.validate(claims);

        // -----------------------------------------------------------------
        // 2. 🔒 ATOMIC CONSUMPTION (ANTI-REPLAY, DISTRIBUTED SAFE)
        // -----------------------------------------------------------------
        Duration remainingTtl = Duration.between(
                Instant.now(),
                Instant.ofEpochSecond(claims.exp())
        );

        boolean firstUse = refreshTokenConsumption.consume(
                claims.jti(),
                remainingTtl
        );

        if (!firstUse) {
            // Replay detected — we need familyId to mitigate
            var tokenData = refreshTokenStore.findByJti(claims.jti())
                    .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));

            refreshTokenStore.revokeFamily(tokenData.familyId());

            throw new RefreshTokenReuseDetectedException(
                    "Refresh token replay detected for family: " + tokenData.familyId());
        }

        // -----------------------------------------------------------------
        // 3. Load persistent token metadata
        // -----------------------------------------------------------------
        var tokenData = refreshTokenStore.findByJti(claims.jti())
                .orElseThrow(() -> new IllegalArgumentException("Refresh token not found"));

        // -----------------------------------------------------------------
        // 4. Defensive reuse check (DB-level safety net)
        // -----------------------------------------------------------------
        if (tokenData.revoked()) {
            refreshTokenStore.revokeFamily(tokenData.familyId());

            throw new RefreshTokenReuseDetectedException(
                    "Refresh token reuse detected for family: " + tokenData.familyId());
        }

        // -----------------------------------------------------------------
        // 5. Expiration safety check (persistence-level)
        // -----------------------------------------------------------------
        if (tokenData.isExpired(Instant.now())) {
            throw new IllegalArgumentException("Refresh token expired");
        }

        // -----------------------------------------------------------------
        // 6. Normal flow — revoke current token
        // -----------------------------------------------------------------
        refreshTokenStore.revoke(claims.jti());

        // -----------------------------------------------------------------
        // 7. Rotate or issue new tokens
        // -----------------------------------------------------------------
        if (rotationHandler.shouldRotate()) {
            return rotationHandler.rotate(claims, tokenData.familyId());
        }

        return resultFactory.newAccessOnly(claims, cmd.refreshToken());
    }
}
