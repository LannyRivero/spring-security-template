package com.lanny.spring_security_template.infrastructure.config;

import java.time.Duration;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.policy.RotationPolicy;
import com.lanny.spring_security_template.application.auth.policy.SessionPolicy;
import com.lanny.spring_security_template.application.auth.policy.TokenPolicyProperties;

/**
 * =====================================================================
 * AuthPolicyConfig
 * =====================================================================
 *
 * Infrastructure-level configuration that adapts {@link SecurityJwtProperties}
 * into strongly typed policy interfaces used by the Application Layer.
 *
 * <p>
 * The goal is to isolate all JWT-related configuration (TTL, issuer, audiences,
 * rotation flags, session limits) from business logic.
 * Application services depend exclusively on:
 * </p>
 *
 * <ul>
 * <li>{@link TokenPolicyProperties}</li>
 * <li>{@link RefreshTokenPolicy}</li>
 * <li>{@link SessionPolicy}</li>
 * <li>{@link RotationPolicy}</li>
 * </ul>
 *
 * <h2>Architectural Role</h2>
 * <p>
 * These beans form the backbone of token lifecycle rules:
 * </p>
 *
 * <ul>
 * <li><b>TokenPolicyProperties</b> → TTLs, issuer, JWT audiences</li>
 * <li><b>RefreshTokenPolicy</b> → rules for validating refresh tokens</li>
 * <li><b>SessionPolicy</b> → concurrent session limits per user</li>
 * <li><b>RotationPolicy</b> → whether refresh token rotation is enabled</li>
 * </ul>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 * <li>OWASP ASVS 2.8 — Token expiry, audience and issuer validation</li>
 * <li>OWASP ASVS 3.1 — Secure session lifetime and session limits</li>
 * </ul>
 *
 * <h2>Notes</h2>
 * <ul>
 * <li>This config must remain declarative—no business logic allowed.</li>
 * <li>Central location for multi-environment JWT/security behavior.</li>
 * </ul>
 */
@Configuration
public class AuthPolicyConfig {

    /**
     * Adapts {@link SecurityJwtProperties} to {@link TokenPolicyProperties}.
     */
    @Bean
    TokenPolicyProperties tokenPolicyProperties(SecurityJwtProperties props) {
        return new TokenPolicyProperties() {

            @Override
            public Duration accessTokenTtl() {
                return props.accessTtl();
            }

            @Override
            public Duration refreshTokenTtl() {
                return props.refreshTtl();
            }

            @Override
            public String issuer() {
                return props.issuer();
            }

            @Override
            public String accessAudience() {
                return props.accessAudience();
            }

            @Override
            public String refreshAudience() {
                return props.refreshAudience();
            }
        };
    }

    /**
     * Defines refresh token validation rules (audience enforcement).
     */
    @Bean
    RefreshTokenPolicy refreshTokenPolicy(SecurityJwtProperties props) {
        return props::refreshAudience;
    }

    /**
     * Session management rules such as max concurrent sessions per user.
     */
    @Bean
    SessionPolicy sessionPolicy(SecurityJwtProperties props) {
        return props::maxActiveSessions;
    }

    /**
     * Configures whether refresh token rotation is enabled.
     */
    @Bean
    RotationPolicy rotationPolicy(SecurityJwtProperties props) {
        return props::rotateRefreshTokens;
    }
}
