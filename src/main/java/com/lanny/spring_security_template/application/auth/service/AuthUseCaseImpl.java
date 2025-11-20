package com.lanny.spring_security_template.application.auth.service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;

import org.springframework.context.annotation.Profile;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.command.*;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.port.out.*;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.model.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.*;
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
    private final SecurityJwtProperties props;
    private final TokenBlacklistGateway blacklist;
    private final AuthMetricsService metrics;
    private final SessionRegistryGateway sessionRegistry;
    private final RefreshTokenStore refreshTokenStore;

    // =====================================================
    // LOGIN
    // =====================================================
    @Override
    public JwtResult login(LoginCommand cmd) {

        User user = userAccountGateway.findByUsernameOrEmail(cmd.username())
                .orElseThrow(() -> new UsernameNotFoundException(cmd.username()));

        user.ensureCanAuthenticate();

        if (!user.passwordMatches(cmd.password(), passwordHasher)) {
            metrics.recordLoginFailure();
            throw new InvalidCredentialsException("Invalid username or password");
        }

        String username = user.username().value();

        // Roles/Scopes como Value Objects
        Set<Role> roles = roleProvider.resolveRoles(username);
        Set<Scope> scopes = scopePolicy.resolveScopes(roles);

        List<String> roleNames = roles.stream().map(Role::name).toList();
        List<String> scopeNames = scopes.stream().map(Scope::name).toList();

        // Tiempos
        Instant now = clockProvider.now();
        Duration accessTtl = props.accessTtl();
        Duration refreshTtl = props.refreshTtl();

        Instant accessExp = now.plus(accessTtl);
        Instant refreshExp = now.plus(refreshTtl);

        // Emitimos tokens
        String accessToken = tokenProvider.generateAccessToken(username, roleNames, scopeNames, accessTtl);
        String refreshToken = tokenProvider.generateRefreshToken(username, refreshTtl);

        // Extraer JTI del refresh token
        String refreshJti = tokenProvider.extractJti(refreshToken);

        // Guardar refresh en DB (persistencia real)
        refreshTokenStore.save(username, refreshJti, now, refreshExp);

        // Registrar sesión
        sessionRegistry.registerSession(username, refreshJti, refreshExp);

        // Limitar sesiones activas
        int maxSessions = props.maxActiveSessions();
        if (maxSessions > 0) {
            var sessions = sessionRegistry.getActiveSessions(username);
            if (sessions.size() > maxSessions) {

                int excess = sessions.size() - maxSessions;

                for (int i = 0; i < excess; i++) {
                    String jtiToRemove = sessions.get(i);

                    // Revocamos el refresh antiguo
                    blacklist.revoke(jtiToRemove, refreshExp);

                    // Eliminamos del registry
                    sessionRegistry.removeSession(username, jtiToRemove);

                    // Eliminamos de BD
                    refreshTokenStore.delete(jtiToRemove);
                }
            }
        }

        metrics.recordLoginSuccess();
        return new JwtResult(accessToken, refreshToken, accessExp);
    }

    // =====================================================
    // REFRESH
    // =====================================================
    @Override
    public JwtResult refresh(RefreshCommand cmd) {

        return tokenProvider.validateAndGetClaims(cmd.refreshToken())
                .map(claims -> {

                    String username = claims.sub();

                    // Validar audiencia
                    if (claims.aud() == null || !claims.aud().contains(props.refreshAudience())) {
                        throw new IllegalArgumentException("Invalid refresh token audience");
                    }

                    // Anti-replay real: El refresh debe existir en BD
                    if (!refreshTokenStore.exists(claims.jti())) {
                        throw new IllegalArgumentException("Refresh token not found (revoked or expired)");
                    }

                    // Anti-replay: ¿revocado?
                    if (blacklist.isRevoked(claims.jti())) {
                        throw new IllegalArgumentException("Refresh token revoked or re-used");
                    }

                    // Reconstruir roles/scopes
                    Set<Role> roles = roleProvider.resolveRoles(username);
                    Set<Scope> scopes = scopePolicy.resolveScopes(roles);

                    List<String> roleNames = roles.stream().map(Role::name).toList();
                    List<String> scopeNames = scopes.stream().map(Scope::name).toList();

                    Instant now = clockProvider.now();
                    Duration accessTtl = props.accessTtl();
                    Duration refreshTtl = props.refreshTtl();
                    Instant accessExp = now.plus(accessTtl);
                    Instant refreshExp = now.plus(refreshTtl);

                    // ROTACIÓN
                    if (props.rotateRefreshTokens()) {

                        // 1) Revocamos refresh anterior
                        blacklist.revoke(claims.jti(), Instant.ofEpochSecond(claims.exp()));

                        // 2) Lo eliminamos de BD y del registry
                        refreshTokenStore.delete(claims.jti());
                        sessionRegistry.removeSession(username, claims.jti());

                        // 3) Emitimos nuevos tokens
                        String newRefresh = tokenProvider.generateRefreshToken(username, refreshTtl);
                        String newAccess = tokenProvider.generateAccessToken(username, roleNames, scopeNames, accessTtl);

                        String newJti = tokenProvider.extractJti(newRefresh);

                        // 4) Guardamos en BD y session registry
                        refreshTokenStore.save(username, newJti, now, refreshExp);
                        sessionRegistry.registerSession(username, newJti, refreshExp);

                        metrics.recordTokenRefresh();
                        return new JwtResult(newAccess, newRefresh, accessExp);
                    }

                    // SIN rotación → nuevo access, refresh igual
                    String newAccess = tokenProvider.generateAccessToken(username, roleNames, scopeNames, accessTtl);
                    return new JwtResult(newAccess, cmd.refreshToken(), accessExp);

                })
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }

    // =====================================================
    // ME
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
                scopes.stream().map(Scope::name).toList()
        );
    }

    // =====================================================
    // DEV REGISTER
    // =====================================================
    @Override
    @Profile("dev")
    public void registerDev(RegisterCommand cmd) {

        User newUser = new User(
                null,
                Username.of(cmd.username()),
                EmailAddress.of(cmd.email()),
                PasswordHash.of(passwordHasher.hash(cmd.rawPassword())),
                UserStatus.ACTIVE,
                cmd.roles(),
                cmd.scopes()
        );

        userAccountGateway.save(newUser);
        metrics.recordUserRegistration();

        System.out.printf("[DEV] Seed user created: %s%n", newUser.username().value());
    }
}

