package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.RotationPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.event.SecurityEvent;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

/**
 * Handles the full refresh token rotation lifecycle in a secure, auditable way.
 *
 * <p>
 * Responsibilities:
 * <ul>
 * <li>Revoke the old refresh token and register it in blacklist.</li>
 * <li>Remove associated session entries from registry and store.</li>
 * <li>Issue new access/refresh tokens and persist the new session.</li>
 * <li>Publish audit events for traceability (rotation + issuance).</li>
 * </ul>
 * </p>
 *
 * <p>
 * All operations are timestamped using {@link ClockProvider}
 * and logged with contextual MDC trace identifiers.
 * </p>
 */
@Component
@RequiredArgsConstructor
public class TokenRotationHandler {

    private static final Logger log = LoggerFactory.getLogger(TokenRotationHandler.class);

    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final SessionRegistryGateway sessionRegistry;
    private final TokenBlacklistGateway blacklist;
    private final RotationPolicy rotationPolicy;
    private final AuthMetricsService metrics;
    private final ClockProvider clockProvider;
    private final AuditEventPublisher auditEventPublisher;

    /**
     * Determines whether rotation is enabled based on the current
     * {@link RotationPolicy}.
     *
     * @return true if rotation is active; false otherwise
     */
    public boolean shouldRotate() {
        return rotationPolicy.isRotationEnabled();
    }

    /**
     * Performs full rotation of a refresh token, revoking the old one
     * and issuing new tokens for the given user.
     *
     * <p>
     * The rotation flow guarantees:
     * <ul>
     * <li>Old token revocation (blacklist + session cleanup)</li>
     * <li>New token persistence and session registration</li>
     * <li>Audit and metrics consistency</li>
     * </ul>
     * </p>
     *
     * @param claims parsed JWT claims from the old refresh token
     * @return {@link JwtResult} containing new tokens
     */
    public JwtResult rotate(JwtClaimsDTO claims) {
        final String username = claims.sub();
        final String traceId = MDC.get("traceId");
        final Instant now = clockProvider.now();

        // Step 1: resolve roles/scopes
        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // Step 2: revoke old token
        blacklist.revoke(claims.jti(), Instant.ofEpochSecond(claims.exp()));
        refreshTokenStore.delete(claims.jti());
        sessionRegistry.removeSession(username, claims.jti());

        auditEventPublisher.publishAuthEvent(
                SecurityEvent.TOKEN_REVOKED.name(),
                username,
                now,
                "Old refresh token revoked during rotation");
        log.info("[TOKEN_ROTATION] user={} trace={} event=revoked jti={}", username, traceId, claims.jti());

        // Step 3: issue new tokens
        IssuedTokens tokens = tokenIssuer.issueTokens(username, rs);

        // Step 4: persist and register session
        refreshTokenStore.save(username, tokens.refreshJti(), tokens.issuedAt(), tokens.refreshExp());
        sessionRegistry.registerSession(username, tokens.refreshJti(), tokens.refreshExp());

        // Step 5: metrics + audit
        metrics.recordTokenRefresh();

        auditEventPublisher.publishAuthEvent(
                SecurityEvent.TOKEN_ISSUED.name(),
                username,
                now,
                "New access and refresh tokens issued after rotation");
        log.info("[TOKEN_ROTATION] user={} trace={} event=issued newJti={}", username, traceId, tokens.refreshJti());

        return tokens.toJwtResult();
    }
}
