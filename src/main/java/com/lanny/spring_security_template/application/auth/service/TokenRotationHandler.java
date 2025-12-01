package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;

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
 * Handles secure, auditable refresh token rotation.
 *
 * <p>
 * This component performs the full lifecycle of a refresh token rotation:
 * <ul>
 * <li>Revokes and blacklists the old refresh token.</li>
 * <li>Deletes its persistent record and session references.</li>
 * <li>Issues new access/refresh tokens using {@link TokenIssuer}.</li>
 * <li>Persists and registers the new session.</li>
 * <li>Publishes {@link SecurityEvent} audit logs and updates metrics.</li>
 * </ul>
 * </p>
 *
 * <h2>Design Principles</h2>
 * <ul>
 * <li>Stateless and deterministic logic driven by {@link RotationPolicy}.</li>
 * <li>Fully auditable through {@link AuditEventPublisher} and MDC trace
 * context.</li>
 * <li>Safe to execute concurrently thanks to isolation per refresh JTI.</li>
 * </ul>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 * <li>OWASP ASVS 2.8.5 – “Rotate refresh tokens after each use.”</li>
 * <li>OWASP ASVS 2.10.3 – “Log all token issuance and revocation events.”</li>
 * <li>OWASP ASVS 2.8.3 – “Limit and manage active sessions.”</li>
 * </ul>
 */
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
     * Checks if refresh token rotation is enabled via {@link RotationPolicy}.
     *
     * @return true if rotation is enabled, false otherwise
     */
    public boolean shouldRotate() {
        return rotationPolicy.isRotationEnabled();
    }

    /**
     * Performs a secure refresh token rotation:
     * <ol>
     * <li>Revokes and blacklists the old refresh token.</li>
     * <li>Removes its session references and persistent entry.</li>
     * <li>Issues a new token pair and persists the new session.</li>
     * <li>Records metrics and audit events for compliance.</li>
     * </ol>
     *
     * @param claims parsed JWT claims from the old refresh token
     * @return {@link JwtResult} containing new access and refresh tokens
     */
    public JwtResult rotate(JwtClaimsDTO claims) {
        final String username = claims.sub();
        final String traceId = MDC.get("traceId");
        final Instant now = clockProvider.now();

        // Step 1️ Resolve current roles and scopes
        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // Step 2️ Revoke old refresh token
        blacklist.revoke(claims.jti(), Instant.ofEpochSecond(claims.exp()));
        refreshTokenStore.delete(claims.jti());
        sessionRegistry.removeSession(username, claims.jti());

        auditEventPublisher.publishAuthEvent(
                SecurityEvent.TOKEN_REVOKED.name(),
                username,
                now,
                "Old refresh token revoked during rotation.");
        log.info("[TOKEN_ROTATION] user={} trace={} event=revoked jti={}", username, traceId, claims.jti());

        // Step 3️ Issue new token pair
        IssuedTokens tokens = tokenIssuer.issueTokens(username, rs);

        // Step 4️ Persist and register the new session
        refreshTokenStore.save(username, tokens.refreshJti(), tokens.issuedAt(), tokens.refreshExp());
        sessionRegistry.registerSession(username, tokens.refreshJti(), tokens.refreshExp());

        // Step 5️ Metrics and auditing
        metrics.recordTokenRefresh();
        auditEventPublisher.publishAuthEvent(
                SecurityEvent.TOKEN_ISSUED.name(),
                username,
                now,
                "New access and refresh tokens issued after rotation.");
        log.info("[TOKEN_ROTATION] user={} trace={} event=issued newJti={}", username, traceId, tokens.refreshJti());

        return tokens.toJwtResult();
    }
}
