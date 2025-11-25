package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

/**
 * Creates a new access token (without refresh rotation)
 * using the current refresh token as-is.
 */
@Component
@RequiredArgsConstructor
public class TokenRefreshResultFactory {

    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenProvider tokenProvider;
    private final ClockProvider clockProvider;
    private final SecurityJwtProperties props;

    public JwtResult newAccessOnly(JwtClaimsDTO claims, String refreshToken) {
        String username = claims.sub();

        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        Instant now = clockProvider.now();
        Duration accessTtl = props.accessTtl();
        Instant accessExp = now.plus(accessTtl);

        String newAccess = tokenProvider.generateAccessToken(
                username,
                rs.roleNames(),
                rs.scopeNames(),
                accessTtl
        );

        return new JwtResult(newAccess, refreshToken, accessExp);
    }
}

