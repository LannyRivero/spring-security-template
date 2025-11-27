package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;
import java.util.UUID;

import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.event.SecurityEvent;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

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
    private final ClockProvider clockProvider;
    private final AuditEventPublisher auditEventPublisher;

    /**
     * Refreshes a JWT session using a valid refresh token.
     *
     * @param cmd refresh command containing the token
     * @return new JWT access/refresh pair or access-only result
     */
    public JwtResult refresh(RefreshCommand cmd) {
        String traceId = UUID.randomUUID().toString();
        MDC.put("traceId", traceId);

        try {

            return tokenProvider.validateAndGetClaims(cmd.refreshToken())
                    .map(claims -> handleRefresh(claims, cmd))
                    .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
        } finally {
            MDC.clear();
        }
    }

    private JwtResult handleRefresh(JwtClaimsDTO claims, RefreshCommand cmd) {
        String username = claims.sub();

        MDC.put("username", username);

        // Step 1️ Validate refresh token integrity
        validator.validate(claims);

        JwtResult result;
        Instant now = clockProvider.now();

        // Step 2️ Handle rotation vs simple access renewal
        if (rotationHandler.shouldRotate()) {
            result = rotationHandler.rotate(claims);
            auditEventPublisher.publishAuthEvent(
                    SecurityEvent.TOKEN_ROTATED.name(),
                    username,
                    now,
                    "Refresh token rotated and new session issued");
        } else {
            result = resultFactory.newAccessOnly(claims, cmd.refreshToken());
            auditEventPublisher.publishAuthEvent(
                    SecurityEvent.TOKEN_REFRESH.name(),
                    username,
                    now,
                    "Access token refreshed without rotation");
        }

        return result;
    }
}
