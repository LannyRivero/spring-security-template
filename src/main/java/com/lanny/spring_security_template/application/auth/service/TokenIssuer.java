package com.lanny.spring_security_template.application.auth.service;

import java.time.Duration;
import java.time.Instant;


import com.lanny.spring_security_template.application.auth.policy.TokenPolicyProperties;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

/**
 * Responsible for issuing signed JWT access and refresh tokens.
 *
 * <p>
 * This component coordinates the {@link TokenProvider} and
 * {@link TokenPolicyProperties}
 * to generate time-bound tokens according to the configured security policy.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Generate access and refresh tokens using cryptographic signing (via
 * {@link TokenProvider}).</li>
 * <li>Apply TTLs defined by {@link TokenPolicyProperties}.</li>
 * <li>Attach user roles and scopes to the access token claims.</li>
 * <li>Extract the refresh token JTI (unique identifier) for session
 * management.</li>
 * </ul>
 *
 * <h2>Design Notes</h2>
 * <ul>
 * <li>Does not persist tokens — this is handled by {@code RefreshTokenStore} or
 * {@code SessionManager}.</li>
 * <li>Operates deterministically using a fixed {@link ClockProvider} to enable
 * predictable tests.</li>
 * <li>Forms part of the <b>application layer</b> in the Clean Architecture
 * structure.</li>
 * </ul>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 * <li>OWASP ASVS 2.8.1 – "Use short-lived access tokens and longer-lived
 * refresh tokens."</li>
 * <li>OWASP ASVS 2.10.3 – "Ensure token issuance events are auditable."</li>
 * </ul>
 */
@RequiredArgsConstructor
public class TokenIssuer {

        private final TokenProvider tokenProvider;
        private final ClockProvider clockProvider;
        private final TokenPolicyProperties tokenPolicy;

        /**
         * Issues a new pair of JWT tokens (access + refresh) with attached metadata.
         *
         * @param username the subject for which the tokens are issued
         * @param rs       resolved roles and scopes
         * @return {@link IssuedTokens} containing both access and refresh tokens with
         *         TTLs
         */
        public IssuedTokens issueTokens(String username, RoleScopeResult rs) {

                // Step 1: Retrieve current timestamp and TTLs from policy
                Instant now = clockProvider.now();
                Duration accessTtl = tokenPolicy.accessTokenTtl();
                Duration refreshTtl = tokenPolicy.refreshTokenTtl();

                Instant accessExp = now.plus(accessTtl);
                Instant refreshExp = now.plus(refreshTtl);

                // Step 2: Generate tokens using the provider
                String accessToken = tokenProvider.generateAccessToken(
                                username,
                                rs.roleNames(),
                                rs.scopeNames(),
                                accessTtl);

                String refreshToken = tokenProvider.generateRefreshToken(
                                username,
                                refreshTtl);

                // Step 3: Extract JTI for refresh token tracking
                String refreshJti = tokenProvider.extractJti(refreshToken);

                // Step 4: Return issued tokens with full metadata
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
