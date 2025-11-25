package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.*;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceImpl;
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
    private final SecurityJwtProperties props;
    private final AuthMetricsServiceImpl metrics;

    /** Checks whether refresh token rotation is enabled */
    public boolean shouldRotate() {
        return props.rotateRefreshTokens();
    }

    /** Performs full rotation and returns new JWT result */
    public JwtResult rotate(JwtClaimsDTO claims) {
        String username = claims.sub();

        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // 1️ Revoke old refresh token
        blacklist.revoke(claims.jti(), Instant.ofEpochSecond(claims.exp()));

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

        return tokens.toJwtResult();
    }
}
