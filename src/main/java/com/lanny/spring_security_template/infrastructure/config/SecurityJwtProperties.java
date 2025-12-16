package com.lanny.spring_security_template.infrastructure.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Strongly-typed configuration for JWT issuance, validation and rotation.
 *
 * Loaded under prefix: security.jwt.*
 *
 * Fully enterprise-ready (OWASP ASVS 2.x / 3.x compliant).
 */
@ConfigurationProperties(prefix = "security.jwt")
public record SecurityJwtProperties(

                /** Token issuer (iss claim). Must uniquely identify this auth server. */
                @NotBlank(message = "issuer must not be blank") @DefaultValue("spring-security-template") String issuer,

                /** Audience expected in access tokens. */
                @NotBlank(message = "accessAudience must not be blank") @DefaultValue("access") String accessAudience,

                /** Audience expected in refresh tokens. */
                @NotBlank(message = "refreshAudience must not be blank") @DefaultValue("refresh") String refreshAudience,

                /** Access token TTL (ISO-8601 duration: PT15M, PT10M...) */
                @NotNull(message = "accessTtl must be provided") @DefaultValue("PT15M") Duration accessTtl,

                /** Refresh token TTL (ISO-8601 duration: P7D, P14D...) */
                @NotNull(message = "refreshTtl must be provided") @DefaultValue("P7D") Duration refreshTtl,

                /** Signing algorithm (RSA or HMAC). */
                @NotNull(message = "algorithm must be specified") @DefaultValue("RSA") JwtAlgorithm algorithm,

                /** Whether refresh tokens should be rotated (ASVS 2.8.4). */
                @DefaultValue("false") boolean rotateRefreshTokens,

                /** Default RBAC roles assigned to new users. */
                @DefaultValue( {
                }) List<String> defaultRoles,

                /** Default OAuth-like scopes for new users. */
                @DefaultValue({}) List<String> defaultScopes,

                /** Maximum number of concurrent sessions allowed per user. */
                @Min(value = 1, message = "maxActiveSessions must be >= 1") @DefaultValue("1") int maxActiveSessions){
}
