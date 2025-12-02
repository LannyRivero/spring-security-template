package com.lanny.spring_security_template.infrastructure.config;

import java.time.Duration;
import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

/**
 * Strongly-typed configuration for JWT issuance, validation and rotation.
 *
 * <p>
 * This record binds properties under the prefix {@code security.jwt.*}
 * and centralizes all runtime parameters required by the authentication system.
 * </p>
 *
 * <h2>Key Responsibilities</h2>
 * <ul>
 * <li>Provide issuer and audience claims for JWT validation.</li>
 * <li>Define TTL (expiration) for access and refresh tokens.</li>
 * <li>Control refresh-token rotation policy.</li>
 * <li>Configure default RBAC roles and OAuth-like scopes for new accounts.</li>
 * <li>Enforce a global limit of concurrent sessions per user.</li>
 * </ul>
 *
 * <h2>Security Notes</h2>
 * <ul>
 * <li><b>issuer</b> must uniquely identify this authentication authority.</li>
 * <li><b>accessAudience</b> and <b>refreshAudience</b> must differ to avoid
 * replay misuse.</li>
 * <li><b>rotateRefreshTokens</b> enables ASVS 2.8.4-compliant rotation.</li>
 * <li><b>maxActiveSessions</b> enforces OWASP ASVS 2.6.3 recommended session
 * controls.</li>
 * </ul>
 *
 * <h2>Extensibility</h2>
 * <p>
 * Future versions may add:
 * </p>
 * <ul>
 * <li>KID (Key ID) for key pinning when using key rotation.</li>
 * <li>Key source strategy: classpath, filesystem, keystore.</li>
 * <li>Support for multiple signing keys.</li>
 * </ul>
 */
@ConfigurationProperties(prefix = "security.jwt")
public record SecurityJwtProperties(

                /** Token issuer (iss claim) */
                @DefaultValue("spring-security-template") String issuer,

                /** Expected audience for access tokens (aud claim) */
                @DefaultValue("access") String accessAudience,

                /** Expected audience for refresh tokens */
                @DefaultValue("refresh") String refreshAudience,

                /** Access token lifetime (ISO-8601 duration, ex: PT15M) */
                @DefaultValue("PT15M") Duration accessTtl,

                /** Refresh token lifetime (ISO-8601 duration, ex: P7D) */                
                @DefaultValue("P7D") Duration refreshTtl,

                /** Signing algorithm used (RSA or HMAC) */
                @DefaultValue("RSA") String algorithm,

                /** Whether refresh tokens should be rotated (recommended for security) */
                @DefaultValue("false") boolean rotateRefreshTokens,

                /** Default RBAC roles assigned to newly registered users */
                @DefaultValue( {
                }) List<String> defaultRoles,

                /** Default scopes granted to new users */
                @DefaultValue({}) List<String> defaultScopes,

                /** Max allowed concurrent sessions per user */
                @DefaultValue("1") int maxActiveSessions){
}
