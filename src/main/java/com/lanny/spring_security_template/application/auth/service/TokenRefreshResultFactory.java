package com.lanny.spring_security_template.application.auth.service;

import java.time.Duration;
import java.time.Instant;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.TokenPolicyProperties;
import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

/**
 *  Generates a new Access Token from an existing Refresh Token.
 *
 * <p>
 * This factory is used when a user requests a token refresh
 * without rotating the refresh token (i.e., the same refresh token
 * remains valid). It leverages {@link RoleProvider} and {@link ScopePolicy}
 * to dynamically embed current user roles and scopes into the new
 * access token claims.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Derive roles and scopes for the user from domain policies.</li>
 * <li>Compute the new access token expiration time based on
 * {@link TokenPolicyProperties}.</li>
 * <li>Delegate cryptographic generation to {@link TokenProvider}.</li>
 * <li>Return a {@link JwtResult} combining the new access token with the same
 * refresh token.</li>
 * </ul>
 *
 * <h2>Design Notes</h2>
 * <ul>
 * <li>Stateless, deterministic, and fully testable component.</li>
 * <li>Used internally by {@link RefreshService} when rotation is disabled.</li>
 * <li>Does not modify the refresh token or session store.</li>
 * </ul>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 * <li>OWASP ASVS 2.8.1 – Short-lived access tokens with renewable refresh.</li>
 * <li>OWASP ASVS 2.10.3 – Auditable token lifecycle events.</li>
 * </ul>
 *
 * <h2>Example</h2>
 * 
 * <pre>{@code
 * JwtResult result = tokenRefreshResultFactory.newAccessOnly(claims, refreshToken);
 * return ResponseEntity.ok(result);
 * }</pre>
 */
@Component
@RequiredArgsConstructor
public class TokenRefreshResultFactory {

    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;
    private final TokenProvider tokenProvider;
    private final ClockProvider clockProvider;
    private final TokenPolicyProperties tokenPolicy;

    /**
     * Creates a new access token while keeping the existing refresh token.
     *
     * @param claims       claims extracted from the refresh token
     * @param refreshToken current valid refresh token
     * @return a {@link JwtResult} containing a new access token and the same
     *         refresh token
     */
    public JwtResult newAccessOnly(JwtClaimsDTO claims, String refreshToken) {
        String username = claims.sub();

        //  Step 1: Resolve current roles and scopes
        RoleScopeResult rs = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        //  Step 2: Compute TTL and expiration time
        Instant now = clockProvider.now();
        Duration accessTtl = tokenPolicy.accessTokenTtl();
        Instant accessExp = now.plus(accessTtl);

        //  Step 3: Generate new access token with updated claims
        String newAccess = tokenProvider.generateAccessToken(
                username,
                rs.roleNames(),
                rs.scopeNames(),
                accessTtl);

        //  Step 4: Return new access token + existing refresh
        return new JwtResult(newAccess, refreshToken, accessExp);
    }
}
