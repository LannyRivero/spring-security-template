package com.lanny.spring_security_template.application.auth.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.ScopePolicy;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.shared.ClockProvider;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AuthUseCaseImpl implements AuthUseCase {

    private final UserAccountGateway userAccountGateway;
    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenProvider tokenProvider;
    private final PasswordEncoder passwordEncoder;
    private final ClockProvider clockProvider;

    @Override
    public JwtResult login(LoginCommand command) {
        // 1) Buscar usuario
        User user = userAccountGateway.findByUsernameOrEmail(command.username())
                .orElseThrow(() -> new UsernameNotFoundException(command.username()));

        // 2) Validar estado de la cuenta (regla de dominio)
        user.ensureCanAuthenticate();

        // 3) Validar credenciales
        if (!user.passwordMatches(command.password(), passwordEncoder)) {
            throw new InvalidCredentialsException("Invalid username or password");
        }

        // 4) Calcular roles y scopes
        List<String> roles = roleProvider.resolveRoles(user.username());
        List<String> scopes = scopePolicy.resolveScopes(roles);

        // 5) Duraciones (pueden venir de SecurityJwtProperties)
        Duration accessTtl = Duration.ofMinutes(15);
        Duration refreshTtl = Duration.ofDays(30);

        // 6) Instantes deterministas desde ClockProvider
        Instant issuedAt = clockProvider.now();
        Instant accessExp = issuedAt.plus(accessTtl);

        // 7) Generar tokens
        String accessToken = tokenProvider.generateAccessToken(user.username(), roles, scopes, accessTtl);
        String refreshToken = tokenProvider.generateRefreshToken(user.username(), refreshTtl);

        // 8) Devolver resultado con expiración exacta
        return new JwtResult(accessToken, refreshToken, accessExp);
    }

    @Override
    public JwtResult refresh(RefreshCommand command) {
        return tokenProvider.parseClaims(command.refreshToken())
                .map(claims -> {
                    String username = claims.sub();
                    List<String> roles = roleProvider.resolveRoles(username);
                    List<String> scopes = scopePolicy.resolveScopes(roles);

                    Duration accessTtl = Duration.ofMinutes(15);
                    Instant issuedAt = clockProvider.now();
                    Instant expiresAt = issuedAt.plus(accessTtl);

                    String newAccess = tokenProvider.generateAccessToken(username, roles, scopes, accessTtl);

                    return new JwtResult(newAccess, command.refreshToken(), expiresAt);
                })
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    @Override
    public MeResult me(String username) {
        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        List<String> roles = roleProvider.resolveRoles(username);
        List<String> scopes = scopePolicy.resolveScopes(roles);

        return new MeResult(user.id(), username, roles, scopes);
    }

    @Override
    @Profile("dev")
    public void registerDev(RegisterCommand command) {
        // Pendiente: crear usuario de desarrollo
    }
}
