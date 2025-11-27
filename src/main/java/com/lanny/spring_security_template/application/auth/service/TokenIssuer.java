package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.policy.TokenPolicyProperties;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.time.Instant;

@Component
@RequiredArgsConstructor
public class TokenIssuer {

    private final TokenProvider tokenProvider;
    private final ClockProvider clockProvider;
    private final TokenPolicyProperties tokenPolicy;

    public IssuedTokens issueTokens(String username, RoleScopeResult rs) {

        Instant now = clockProvider.now();
        Duration accessTtl = tokenPolicy.accessTokenTtl();
        Duration refreshTtl = tokenPolicy.refreshTokenTtl();

        Instant accessExp = now.plus(accessTtl);
        Instant refreshExp = now.plus(refreshTtl);

        String accessToken = tokenProvider.generateAccessToken(
                username,
                rs.roleNames(),
                rs.scopeNames(),
                accessTtl);

        String refreshToken = tokenProvider.generateRefreshToken(
                username,
                refreshTtl);

        String refreshJti = tokenProvider.extractJti(refreshToken);

        return new IssuedTokens(
                username,
                accessToken,
                refreshToken,
                refreshJti,
                now,
                accessExp,
                refreshExp,
                rs.roleNames(),
                rs.scopeNames());
    }
}
