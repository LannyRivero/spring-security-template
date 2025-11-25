package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Handles token generation, persistence and session registration.
 */
@Service
@RequiredArgsConstructor
public class TokenSessionCreator {

    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenIssuer tokenIssuer;
    private final SessionManager sessionManager;
    private final RefreshTokenStore refreshTokenStore;

    public JwtResult create(String username) {
        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);
        IssuedTokens tokens = tokenIssuer.issueTokens(username, rs);

        refreshTokenStore.save(username, tokens.refreshJti(), tokens.issuedAt(), tokens.refreshExp());
        sessionManager.register(tokens);

        return tokens.toJwtResult();
    }
}
