package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.policy.RotationPolicy;
import com.lanny.spring_security_template.application.auth.port.out.*;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Handles full refresh token rotation lifecycle:
 * revoke old, issue new, persist and register session.
 */
@Component
@RequiredArgsConstructor
public class TokenRotationHandler {

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

    public boolean shouldRotate() {
        return rotationPolicy.isRotationEnabled();
    }

    public JwtResult rotate(JwtClaimsDTO claims) {
        String username = claims.sub();
        Instant now = clockProvider.now();

        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // 1️ Revoke old refresh token
        blacklist.revoke(claims.jti(), Instant.ofEpochSecond(claims.exp()));
        auditEventPublisher.publishAuthEvent(
            "TOKEN_REVOKED", 
            username, 
            now, 
            "Old refresh token revoked due to rotation");

        // 2️ Remove old session
        refreshTokenStore.delete(claims.jti());
        sessionRegistry.removeSession(username, claims.jti());

        // 3️ Issue new tokens
        IssuedTokens tokens = tokenIssuer.issueTokens(username, rs);

        // 4️ Persist new refresh
        refreshTokenStore.save(username, tokens.refreshJti(), tokens.issuedAt(), tokens.refreshExp());
        sessionRegistry.registerSession(username, tokens.refreshJti(), tokens.refreshExp());

        // 5️ Record metrics
        metrics.recordTokenRefresh();
        auditEventPublisher.publishAuthEvent(
            "TOKEN_ISSUED", 
            username, 
            now, 
            "New refresh and acess tokens issued"
            );

        return tokens.toJwtResult();
    }
}
