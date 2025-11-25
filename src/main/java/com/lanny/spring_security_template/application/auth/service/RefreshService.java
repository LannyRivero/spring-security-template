package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Orchestrates the refresh-token use case:
 * validates token claims, applies rotation if enabled,
 * or generates a new access token otherwise.
 */
@Service
@RequiredArgsConstructor
public class RefreshService {

    private final TokenProvider tokenProvider;
    private final RefreshTokenValidator validator;
    private final TokenRotationHandler rotationHandler;
    private final TokenRefreshResultFactory resultFactory;

    /**
     * Refreshes a JWT session using a valid refresh token.
     *
     * @param cmd refresh command containing the token
     * @return new JWT access/refresh pair or access-only result
     */
    public JwtResult refresh(RefreshCommand cmd) {
        return tokenProvider.validateAndGetClaims(cmd.refreshToken())
                .map(claims -> handleRefresh(claims, cmd))
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    private JwtResult handleRefresh(JwtClaimsDTO claims, RefreshCommand cmd) {
        // Step 1️ Validate refresh token integrity
        validator.validate(claims);

        // Step 2️ Handle rotation vs simple access renewal
        if (rotationHandler.shouldRotate()) {
            return rotationHandler.rotate(claims);
        }

        return resultFactory.newAccessOnly(claims, cmd.refreshToken());
    }
}
