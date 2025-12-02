package com.lanny.spring_security_template.infrastructure.config;

import java.time.Duration;
import java.util.Objects;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.policy.RotationPolicy;
import com.lanny.spring_security_template.application.auth.policy.SessionPolicy;
import com.lanny.spring_security_template.application.auth.policy.TokenPolicyProperties;

/**
 * =====================================================================
 * AuthPolicyConfig (Enterprise Version)
 * =====================================================================
 *
 * Adapts {@link SecurityJwtProperties} into strongly typed policy
 * interfaces consumed by the Application Layer.
 *
 * All validations here are fail-fast so that the application refuses
 * to start if critical JWT configuration is missing or unsafe.
 *
 * SECURITY HARDENING:
 * - issuer must be non-null
 * - audiences must be non-null
 * - TTL values already validated in SecurityJwtPropertiesValidator
 *
 * These policies govern:
 * - Access token TTL
 * - Refresh token TTL & audience
 * - Session concurrency limits
 * - Refresh rotation strategy
 */
@Configuration
public class AuthPolicyConfig {

    /**
     * Maps SecurityJwtProperties into TokenPolicyProperties.
     * Ensures all JWT-critical fields are present.
     */
    @Bean
    TokenPolicyProperties tokenPolicyProperties(SecurityJwtProperties props) {

        // Fail-fast validation (extra safety beyond validator)
        Objects.requireNonNull(props.issuer(), "issuer cannot be null");
        Objects.requireNonNull(props.accessAudience(), "accessAudience cannot be null");
        Objects.requireNonNull(props.refreshAudience(), "refreshAudience cannot be null");

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
     * Refresh token audience enforcement.
     * This ensures refresh tokens always contain the correct audience.
     */
    @Bean
    RefreshTokenPolicy refreshTokenPolicy(SecurityJwtProperties props) {
        Objects.requireNonNull(props.refreshAudience(), "refreshAudience cannot be null");
        return props::refreshAudience;
    }

    /**
     * Defines session concurrency restrictions.
     */
    @Bean
    SessionPolicy sessionPolicy(SecurityJwtProperties props) {
        return props::maxActiveSessions;
    }

    /**
     * Enables or disables refresh token rotation.
     */
    @Bean
    RotationPolicy rotationPolicy(SecurityJwtProperties props) {
        return props::rotateRefreshTokens;
    }
}
