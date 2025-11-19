package com.lanny.spring_security_template.application.auth.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
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
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.model.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Role;
import com.lanny.spring_security_template.domain.valueobject.Scope;
import com.lanny.spring_security_template.domain.valueobject.Username;
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
        private final PasswordHasher passwordHasher;
        private final ClockProvider clockProvider;
        private final SecurityJwtProperties securityJwtProperties;
        private final TokenBlacklistGateway tokenBlacklistGateway;
        private final AuthMetricsService metrics;

        // =====================================================
        // LOGIN
        // =====================================================
        @Override
        public JwtResult login(LoginCommand command) {

                User user = userAccountGateway.findByUsernameOrEmail(command.username())
                                .orElseThrow(() -> new UsernameNotFoundException(command.username()));

                user.ensureCanAuthenticate();

                if (!user.passwordMatches(command.password(), passwordHasher)) {
                        metrics.recordLoginFailure();
                        throw new InvalidCredentialsException("Invalid username or password");
                }

                // 1️⃣ Roles como Value Objects
                Set<Role> roles = roleProvider.resolveRoles(user.username().value());

                // 2️⃣ Scopes como Value Objects
                Set<Scope> scopes = scopePolicy.resolveScopes(roles);

                // 3️⃣ Convertir dominio → strings para el JWT
                List<String> roleNames = roles.stream()
                                .map(Role::name)
                                .toList();

                List<String> scopeNames = scopes.stream()
                                .map(Scope::name)
                                .toList();

                // 4️⃣ Tiempos
                Duration accessTtl = securityJwtProperties.accessTtl();
                Duration refreshTtl = securityJwtProperties.refreshTtl();

                Instant issuedAt = clockProvider.now();
                Instant accessExp = issuedAt.plus(accessTtl);

                // 5️⃣ Emitir tokens
                String accessToken = tokenProvider.generateAccessToken(
                                user.username().value(),
                                roleNames,
                                scopeNames,
                                accessTtl);

                String refreshToken = tokenProvider.generateRefreshToken(
                                user.username().value(),
                                refreshTtl);

                metrics.recordLoginSuccess();

                return new JwtResult(accessToken, refreshToken, accessExp);
        }

        // =====================================================
        // REFRESH
        // =====================================================
        @Override
        public JwtResult refresh(RefreshCommand command) {

                return tokenProvider.parseClaims(command.refreshToken())
                                .map(claims -> {

                                        // 1) Validar que es un REFRESH TOKEN (audiencia)
                                        String expectedRefreshAudience = securityJwtProperties.refreshAudience();
                                        if (claims.aud() == null || !claims.aud().contains(expectedRefreshAudience)) {
                                                throw new IllegalArgumentException("Invalid refresh token audience");
                                        }

                                        // 2) Protección anti-replay (reuso del refresh = FRAUDE)
                                        if (tokenBlacklistGateway.isRevoked(claims.jti())) {
                                                throw new IllegalArgumentException(
                                                                "Refresh token revoked or already used");
                                        }

                                        String username = claims.sub();

                                        // 3) Reconstruir roles + scopes desde providers de dominio
                                        Set<Role> roles = roleProvider.resolveRoles(username);
                                        Set<Scope> scopes = scopePolicy.resolveScopes(roles);

                                        List<String> roleNames = roles.stream().map(Role::name).toList();
                                        List<String> scopeNames = scopes.stream().map(Scope::name).toList();

                                        Duration accessTtl = securityJwtProperties.accessTtl();
                                        Duration refreshTtl = securityJwtProperties.refreshTtl();

                                        Instant issuedAt = clockProvider.now();
                                        Instant accessExp = issuedAt.plus(accessTtl);

                                        // 4) ROTACIÓN DE REFRESH TOKENS (OAuth2-style)
                                        if (securityJwtProperties.rotateRefreshTokens()) {

                                                // Revocar SIEMPRE el refresh usado (anti-replay fuerte)
                                                tokenBlacklistGateway.revoke(
                                                                claims.jti(),
                                                                Instant.ofEpochSecond(claims.exp()));

                                                // Emitimos refresh nuevo + access nuevo
                                                String newRefresh = tokenProvider.generateRefreshToken(username,
                                                                refreshTtl);
                                                String newAccess = tokenProvider.generateAccessToken(
                                                                username,
                                                                roleNames,
                                                                scopeNames,
                                                                accessTtl);

                                                metrics.recordTokenRefresh();

                                                return new JwtResult(newAccess, newRefresh, accessExp);
                                        }

                                        // 5) Sin rotación: emitir SOLO nuevo access token
                                        String newAccess = tokenProvider.generateAccessToken(
                                                        username,
                                                        roleNames,
                                                        scopeNames,
                                                        accessTtl);

                                        return new JwtResult(newAccess, command.refreshToken(), accessExp);

                                })
                                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
        }

        // =====================================================
        // ME / WHOAMI
        // =====================================================
        @Override
        public MeResult me(String username) {

                User user = userAccountGateway.findByUsernameOrEmail(username)
                                .orElseThrow(() -> new IllegalArgumentException("User not found"));

                Set<Role> roles = roleProvider.resolveRoles(username);
                Set<Scope> scopes = scopePolicy.resolveScopes(roles);

                return new MeResult(
                                user.id(),
                                username,
                                roles.stream().map(Role::name).toList(),
                                scopes.stream().map(Scope::name).toList());
        }

        // =====================================================
        // DEV REGISTER
        // =====================================================
        @Override
        @Profile("dev")
        public void registerDev(RegisterCommand command) {

                // 1. Construir usuario del dominio usando Value Objects
                User newUser = new User(
                                null,
                                Username.of(command.username()),
                                EmailAddress.of(command.email()),
                                PasswordHash.of(passwordHasher.hash(command.rawPassword())),
                                UserStatus.ACTIVE,
                                command.roles(),
                                command.scopes());

                // 2. Guardar usando el gateway
                userAccountGateway.save(newUser);

                metrics.recordUserRegistration();

                System.out.printf("[DEV] Seed user created: %s%n", newUser.username().value());
        }

}
