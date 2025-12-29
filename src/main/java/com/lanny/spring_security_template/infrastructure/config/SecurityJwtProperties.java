package com.lanny.spring_security_template.infrastructure.config;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

/**
 * Strongly-typed configuration for JWT issuance, validation and rotation.
 *
 * Prefix: security.jwt
 *
 * Infrastructure-only configuration.
 * All cross-field and conditional validation MUST be handled
 * by a dedicated validator (fail-fast at startup).
 */
@ConfigurationProperties(prefix = "security.jwt")
public record SecurityJwtProperties(

                /** Token issuer (iss claim). */
                @NotBlank @DefaultValue("spring-security-template") String issuer,

                /** Audience for access tokens. */
                @NotBlank @DefaultValue("access") String accessAudience,

                /** Audience for refresh tokens. */
                @NotBlank @DefaultValue("refresh") String refreshAudience,

                /** Access token TTL (ISO-8601, e.g. PT15M). */
                @NotNull @DefaultValue("PT15M") Duration accessTtl,

                /** Refresh token TTL (ISO-8601, e.g. P7D). */
                @NotNull @DefaultValue("P7D") Duration refreshTtl,

                /** Allowed clock skew (seconds). */
                @Min(0) @DefaultValue("60") long allowedClockSkewSeconds,

                /** Signing algorithm. */
                @NotNull @DefaultValue("RSA") JwtAlgorithm algorithm,

                /** Enable refresh token rotation. */
                @DefaultValue("false") boolean rotateRefreshTokens,

                /** Default roles assigned to new users. */
                @DefaultValue( {
                }) List<String> defaultRoles,

                /** Default scopes assigned to new users. */
                @DefaultValue({}) List<String> defaultScopes,

                /** Maximum concurrent sessions per user. */
                @Min(1) @DefaultValue("1") int maxActiveSessions,

                /** HMAC configuration (used when algorithm = HMAC). */
                @Valid HmacProperties hmac,

                /** RSA configuration (used when algorithm = RSA). */
                @Valid RsaProperties rsa){

        // ======================================================
        // RSA CONFIG (MULTI-KID)
        // ======================================================
        public record RsaProperties(

                        /** Key source: filesystem | keystore | classpath */
                        @NotBlank String source,

                        /** Kid used to SIGN new tokens */
                        @NotBlank String activeKid,

                        /** Kids accepted for verification (active + old) */
                        @NotNull List<String> verificationKids,

                        /** Used when source = filesystem | classpath */
                        String privateKeyLocation,

                        /** Used when source = filesystem | classpath */
                        Map<String, String> publicKeys,

                        /** Used when source = keystore */
                        @Valid KeystoreProperties keystore) {
        }

        // ======================================================
        // KEYSTORE CONFIG
        // ======================================================
        public record KeystoreProperties(

                        @NotBlank String path,

                        @NotBlank String type,

                        @NotBlank String password,

                        @NotBlank String keyPassword,

                        /** kid → keystore alias mapping */
                        @NotNull Map<String, String> kidAlias) {
        }

        // ======================================================
        // HMAC CONFIG
        // ======================================================
        public record HmacProperties(

                        /**
                         * Base64-encoded secret.
                         * Required when algorithm = HMAC.
                         */
                        @NotBlank(message = "hmac.secretBase64 must not be blank when algorithm=HMAC") String secretBase64) {
        }
}
