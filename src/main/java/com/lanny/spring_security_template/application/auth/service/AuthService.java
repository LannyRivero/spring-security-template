package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.port.out.*;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.model.User;

import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

@Service
@RequiredArgsConstructor
public class AuthService implements AuthUseCase {

    private final AuthPersistencePort authPersistence;
    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;

    @Override
    public JwtResult login(LoginCommand command) {
        User user = authPersistence.findByUsernameOrEmail(command.username())
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        if (!user.passwordMatches(command.password(), passwordEncoder)) {
            throw new IllegalArgumentException("Invalid credentials");
        }

        List<String> roles = roleProvider.resolveRoles(user.username());
        List<String> scopes = scopePolicy.resolveScopes(roles);

        Duration accessTtl = Duration.ofMinutes(15);
        Duration refreshTtl = Duration.ofDays(30);

        String accessToken = tokenProvider.generateAccessToken(user.username(), roles, scopes, accessTtl);
        String refreshToken = tokenProvider.generateRefreshToken(user.username(), refreshTtl);

        return new JwtResult(accessToken, refreshToken, Instant.now().plus(accessTtl));
    }

    @Override
    public JwtResult refresh(RefreshCommand command) {
        return tokenProvider.parseClaims(command.refreshToken())
                .map(claims -> {
                    String username = claims.sub();
                    List<String> roles = roleProvider.resolveRoles(username);
                    List<String> scopes = scopePolicy.resolveScopes(roles);

                    Duration accessTtl = Duration.ofMinutes(15);
                    String newAccess = tokenProvider.generateAccessToken(username, roles, scopes, accessTtl);

                    return new JwtResult(newAccess, command.refreshToken(), Instant.now().plus(accessTtl));
                })
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    @Override
    public MeResult me(String username) {
        User user = authPersistence.findByUsernameOrEmail(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        List<String> roles = roleProvider.resolveRoles(username);
        List<String> scopes = scopePolicy.resolveScopes(roles);

        return new MeResult(user.id(), username, roles, scopes);
    }
}
