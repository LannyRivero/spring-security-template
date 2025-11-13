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
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsService;
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
    private final SecurityJwtProperties securityJwtProperties;
    private final TokenBlacklistGateway tokenBlacklistGateway;
    private final AuthMetricsService metrics; 

    // ===========================
    //  LOGIN
    // ===========================
    @Override
    public JwtResult login(LoginCommand command) {
        try {
            User user = userAccountGateway.findByUsernameOrEmail(command.username())
                    .orElseThrow(() -> new UsernameNotFoundException(command.username()));

            user.ensureCanAuthenticate();

            if (!user.passwordMatches(command.password(), passwordEncoder)) {
                metrics.recordLoginFailure();
                throw new InvalidCredentialsException("Invalid username or password");
            }

            List<String> roles = roleProvider.resolveRoles(user.username());
            List<String> scopes = scopePolicy.resolveScopes(roles);

            Duration accessTtl = securityJwtProperties.accessTtl();
            Duration refreshTtl = securityJwtProperties.refreshTtl();

            Instant issuedAt = clockProvider.now();
            Instant accessExp = issuedAt.plus(accessTtl);

            String accessToken = tokenProvider.generateAccessToken(user.username(), roles, scopes, accessTtl);
            String refreshToken = tokenProvider.generateRefreshToken(user.username(), refreshTtl);

            metrics.recordLoginSuccess(); 

            return new JwtResult(accessToken, refreshToken, accessExp);

        } catch (InvalidCredentialsException e) {
            metrics.recordLoginFailure(); 
            throw e;
        }
    }

    // ===========================
    // REFRESH TOKEN
    // ===========================
    @Override
    public JwtResult refresh(RefreshCommand command) {
        return tokenProvider.parseClaims(command.refreshToken())
                .map(claims -> {
                    if (tokenBlacklistGateway.isRevoked(claims.jti())) {
                        throw new IllegalArgumentException("Refresh token revoked");
                    }

                    String username = claims.sub();
                    List<String> roles = roleProvider.resolveRoles(username);
                    List<String> scopes = scopePolicy.resolveScopes(roles);

                    Duration accessTtl = securityJwtProperties.accessTtl();
                    Duration refreshTtl = securityJwtProperties.refreshTtl();

                    Instant issuedAt = clockProvider.now();
                    Instant accessExp = issuedAt.plus(accessTtl);

                    if (securityJwtProperties.rotateRefreshTokens()) {
                        tokenBlacklistGateway.revoke(claims.jti(), Instant.ofEpochSecond(claims.exp()));

                        String newRefresh = tokenProvider.generateRefreshToken(username, refreshTtl);
                        String newAccess = tokenProvider.generateAccessToken(username, roles, scopes, accessTtl);

                        metrics.recordTokenRefresh(); 

                        return new JwtResult(newAccess, newRefresh, accessExp);
                    }

                    String newAccess = tokenProvider.generateAccessToken(username, roles, scopes, accessTtl);
                    return new JwtResult(newAccess, command.refreshToken(), accessExp);
                })
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    // ===========================
    //  ME
    // ===========================
    @Override
    public MeResult me(String username) {
        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        List<String> roles = roleProvider.resolveRoles(username);
        List<String> scopes = scopePolicy.resolveScopes(roles);

        return new MeResult(user.id(), username, roles, scopes);
    }

    // ===========================
    //  DEV REGISTER
    // ===========================
    @Override
    @Profile("dev")
    public void registerDev(RegisterCommand command) {
        // 🚧 Pendiente: crear usuario de desarrollo
    }
}

