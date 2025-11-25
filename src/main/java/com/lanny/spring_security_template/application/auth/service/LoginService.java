package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class LoginService {

    private final UserAccountGateway userAccountGateway;
    private final PasswordHasher passwordHasher;
    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenIssuer tokenIssuer;
    private final SessionManager sessionManager;
    private final RefreshTokenStore refreshTokenStore;
    private final AuthMetricsServiceImpl metrics;

    public JwtResult login(LoginCommand cmd) {

        User user = userAccountGateway.findByUsernameOrEmail(cmd.username())
                .orElseThrow(() -> new UsernameNotFoundException(cmd.username()));

        // Validación de estado (locked, disabled, deleted)
        user.ensureCanAuthenticate();

        // Validación de contraseña 
        try {
            user.verifyPassword(cmd.password(), passwordHasher);
        } catch (InvalidCredentialsException e) {
            metrics.recordLoginFailure();
            throw new InvalidCredentialsException("Invalid username or password");
        }

        String username = user.username().value();

        // 1) Roles + Scopes
        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // 2) Emitir tokens
        IssuedTokens tokens = tokenIssuer.issueTokens(username, rs);

        // 3) Guardar refresh en DB
        refreshTokenStore.save(
                username,
                tokens.refreshJti(),
                tokens.issuedAt(),
                tokens.refreshExp());

        // 4) Registrar sesión
        sessionManager.register(tokens);

        metrics.recordLoginSuccess();

        return tokens.toJwtResult();
    }

}
