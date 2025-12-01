package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;

import com.lanny.spring_security_template.application.auth.policy.RotationPolicy;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.SessionRegistryGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

import lombok.RequiredArgsConstructor;

/**
 * Pure application service that performs refresh token rotation.
 * 
 * NO logging, NO auditing, NO MDC.
 * All cross-cutting concerns are handled in the AuthUseCaseLoggingDecorator.
 */
@RequiredArgsConstructor
public class TokenRotationHandler {

    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenIssuer tokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final SessionRegistryGateway sessionRegistry;
    private final TokenBlacklistGateway blacklist;
    private final RotationPolicy rotationPolicy;

    public boolean shouldRotate() {
        return rotationPolicy.isRotationEnabled();
    }

    /**
     * Executes secure refresh token rotation logic.
     * 
     * @param claims JWT refresh token claims
     * @return JwtResult containing new access + refresh tokens
     */
    public JwtResult rotate(JwtClaimsDTO claims) {

        String username = claims.sub();

        // 1. Resolve roles + scopes
        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // 2. Revoke & delete old token
        blacklist.revoke(claims.jti(), Instant.ofEpochSecond(claims.exp()));
        refreshTokenStore.delete(claims.jti());
        sessionRegistry.removeSession(username, claims.jti());

        // 3. Issue new token pair
        IssuedTokens tokens = tokenIssuer.issueTokens(username, rs);

        // 4. Persist new session
        refreshTokenStore.save(username, tokens.refreshJti(), tokens.issuedAt(), tokens.refreshExp());
        sessionRegistry.registerSession(username, tokens.refreshJti(), tokens.refreshExp());

        return tokens.toJwtResult();
    }
}
