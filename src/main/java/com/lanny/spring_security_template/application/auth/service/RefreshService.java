package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.*;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
@RequiredArgsConstructor
public class RefreshService {

    private final TokenProvider tokenProvider;
    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final RefreshTokenStore refreshTokenStore;
    private final SessionRegistryGateway sessionRegistry;
    private final TokenBlacklistGateway blacklist;
    private final SecurityJwtProperties props;
    private final ClockProvider clockProvider;
    private final TokenIssuer tokenIssuer;
    private final AuthMetricsServiceImpl metrics;

    public JwtResult refresh(RefreshCommand cmd) {

        return tokenProvider.validateAndGetClaims(cmd.refreshToken())
                .map(claims -> {

                    String username = claims.sub();

                    // 1) Validar audiencia (refresh)
                    if (claims.aud() == null || !claims.aud().contains(props.refreshAudience())) {
                        throw new IllegalArgumentException("Invalid refresh token audience");
                    }

                    // 2) Debe existir en la tabla refresh_tokens
                    if (!refreshTokenStore.exists(claims.jti())) {
                        throw new IllegalArgumentException("Refresh token not found (revoked or expired)");
                    }

                    // 3) Anti-replay: ¿revocado?
                    if (blacklist.isRevoked(claims.jti())) {
                        throw new IllegalArgumentException("Refresh token revoked or re-used");
                    }

                    // 4) Reconstruir roles + scopes
                    RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

                    Instant now = clockProvider.now();
                    Duration accessTtl = props.accessTtl();
                    Instant accessExp = now.plus(accessTtl);

                    // 5) ROTACIÓN
                    if (props.rotateRefreshTokens()) {

                        // 5.1 Revocamos refresh viejo
                        blacklist.revoke(claims.jti(), Instant.ofEpochSecond(claims.exp()));

                        // 5.2 Limpiamos BD + session registry
                        refreshTokenStore.delete(claims.jti());
                        sessionRegistry.removeSession(username, claims.jti());

                        // 5.3 Emitimos nuevos tokens
                        IssuedTokens tokens = tokenIssuer.issueTokens(username, rs);

                        // 5.4 Persistimos nuevo refresh
                        refreshTokenStore.save(
                                username,
                                tokens.refreshJti(),
                                tokens.issuedAt(),
                                tokens.refreshExp());

                        // 5.5 Registramos nueva sesión
                        sessionRegistry.registerSession(username, tokens.refreshJti(), tokens.refreshExp());

                        metrics.recordTokenRefresh();

                        return tokens.toJwtResult();
                    }

                    // 6) SIN rotación → solo nuevo access
                    String newAccess = tokenProvider.generateAccessToken(
                            username,
                            rs.roleNames(),
                            rs.scopeNames(),
                            accessTtl);

                    return new JwtResult(newAccess, cmd.refreshToken(), accessExp);

                })
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh token"));
    }
}
