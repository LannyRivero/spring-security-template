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
 * Application service that orchestrates the refresh-token flow.
 *
 * <p>
 * This service validates a refresh token, applies optional rotation,
 * and issues new access or refresh tokens accordingly.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Validate refresh token integrity via {@link TokenProvider} and
 * {@link RefreshTokenValidator}.</li>
 * <li>Determine if rotation is required using
 * {@link TokenRotationHandler}.</li>
 * <li>Issue a new access token (with or without rotation) through
 * {@link TokenRefreshResultFactory}.</li>
 * <li>Emit audit events using {@link AuditEventPublisher} for traceability and
 * compliance.</li>
 * </ul>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 * <li>OWASP ASVS 2.7.1 — "Use short-lived tokens and refresh securely".</li>
 * <li>OWASP ASVS 2.7.3 — "Detect and invalidate reused or rotated refresh
 * tokens".</li>
 * <li>OWASP ASVS 2.10.3 — "Log all session management events".</li>
 * </ul>
 *
 * <h2>Design Notes</h2>
 * <ul>
 * <li>Follows Clean Architecture principles (application orchestration
 * layer).</li>
 * <li>All dependencies injected via constructor for full testability.</li>
 * <li>Uses MDC tracing to correlate security logs and audit events.</li>
 * </ul>
 *
 * <h2>Example Usage</h2>
 * 
 * <pre>{@code
 * JwtResult result = refreshService.refresh(new RefreshCommand(refreshToken));
 * }</pre>
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
     * @param cmd the refresh command containing the refresh token
     * @return {@link JwtResult} — new access and optionally rotated refresh token
     * @throws IllegalArgumentException if the refresh token is invalid or malformed
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

    /**
     * Handles the validated refresh token: decides whether to rotate or reuse,
     * issues tokens, and publishes audit events.
     *
     * @param claims the JWT claims extracted from the refresh token
     * @param cmd    the original refresh command
     * @return {@link JwtResult} containing the updated token(s)
     */
    private JwtResult handleRefresh(JwtClaimsDTO claims, RefreshCommand cmd) {
        String username = claims.sub();
        MDC.put("username", username);

        // 🔹 Step 1: Validate refresh token integrity
        validator.validate(claims);
        Instant now = clockProvider.now();

        JwtResult result;

        // 🔹 Step 2: Determine if token rotation is required
        if (rotationHandler.shouldRotate()) {
            result = rotationHandler.rotate(claims);

            auditEventPublisher.publishAuthEvent(
                    SecurityEvent.TOKEN_ROTATED.name(),
                    username,
                    now,
                    "Refresh token rotated; new session issued.");
        } else {
            result = resultFactory.newAccessOnly(claims, cmd.refreshToken());

            auditEventPublisher.publishAuthEvent(
                    SecurityEvent.TOKEN_REFRESH.name(),
                    username,
                    now,
                    "Access token refreshed without rotation.");
        }

        return result;
    }
}
