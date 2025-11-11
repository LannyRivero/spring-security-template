package com.lanny.spring_security_template.infrastructure.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Central configuration for JWT generation and validation.
 * Maps values from application.yml (security.jwt.*).
 */
@ConfigurationProperties(prefix = "security.jwt")
public record SecurityJwtProperties(
        /** Token issuer (iss claim) */
        @DefaultValue("spring-security-template") String issuer,

        /** Expected audience for access tokens */
        @DefaultValue("access") String accessAudience,

        /** Expected audience for refresh tokens */
        @DefaultValue("refresh") String refreshAudience,

        /** Access token lifetime (ISO-8601 duration) */
        @DefaultValue("PT15M") Duration accessTtl,

        /** Refresh token lifetime (ISO-8601 duration) */
        @DefaultValue("P7D") Duration refreshTtl,

        /** Algorithm used for JWT signing (RSA or HMAC) */
        @DefaultValue("RSA") String algorithm,

        /** Whether refresh tokens should be rotated and the previous one revoked */
        @DefaultValue("false") boolean rotateRefreshTokens,

        /** Default roles assigned to new users (optional) */
        @DefaultValue({}) List<String> defaultRoles,

        /** Default scopes granted to new users (optional) */
        @DefaultValue({}) List<String> defaultScopes
) { }


