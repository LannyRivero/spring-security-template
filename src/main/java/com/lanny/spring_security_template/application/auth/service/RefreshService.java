package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;

import lombok.RequiredArgsConstructor;

/**
 * Pure application service for handling refresh-token operations.
 *
 * No logging, no MDC, no auditing, no Spring.
 * Cross-cutting concerns handled by AuthUseCaseLoggingDecorator.
 */
@RequiredArgsConstructor
public class RefreshService {

    private final TokenProvider tokenProvider;
    private final RefreshTokenValidator validator;
    private final TokenRotationHandler rotationHandler;
    private final TokenRefreshResultFactory resultFactory;

    /**
     * Orchestrates the refresh token process.
     */
    public JwtResult refresh(RefreshCommand cmd) {

        return tokenProvider.validateAndGetClaims(cmd.refreshToken())
                .map(claims -> handleRefresh(claims, cmd))
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    private JwtResult handleRefresh(JwtClaimsDTO claims, RefreshCommand cmd) {
        // Validate token integrity (signature, expiration, jti, etc.)
        validator.validate(claims);

        // Rotation or reuse
        if (rotationHandler.shouldRotate()) {
            return rotationHandler.rotate(claims);
        } else {
            return resultFactory.newAccessOnly(claims, cmd.refreshToken());
        }
    }
}

