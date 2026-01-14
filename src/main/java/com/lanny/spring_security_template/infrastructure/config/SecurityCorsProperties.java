package com.lanny.spring_security_template.infrastructure.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotEmpty;

/**
 * Strongly-typed configuration for Cross-Origin Resource Sharing (CORS).
 *
 * SECURITY NOTES (MANDATORY FOR ENTERPRISE):
 * ------------------------------------------
 * - In production environments, wildcard origins ("*") MUST NOT be allowed.
 * - If allowCredentials = true => browsers reject "*" => fail-fast.
 * - Strict validation prevents silent misconfiguration.
 *
 * This configuration is consumed by WebCommonConfig and enforced by
 * SecurityConfig.
 */
@Validated
@ConfigurationProperties(prefix = "security.cors")
public record SecurityCorsProperties(

                /** Allowed origin URLs (e.g. https://app.company.com) */
                @NotEmpty @DefaultValue({
                                "*" }) List<String> allowedOrigins,

                /** Allowed HTTP methods for cross-origin requests */
                @NotEmpty @DefaultValue({ "GET", "POST", "PUT", "DELETE", "OPTIONS" }) List<String> allowedMethods,

                /** Allowed headers received in CORS requests */
                @NotEmpty @DefaultValue({ "Authorization", "Content-Type" }) List<String> allowedHeaders,

                /** Headers exposed to the browser */
                @DefaultValue({ "X-Correlation-Id" }) List<String> exposedHeaders,

                /** Whether cookies / Authorization headers can be sent cross-origin */
                @DefaultValue("false") boolean allowCredentials) {

        /**
         * Bind-time invariant validation.
         *
         * <p>
         * These rules are ALWAYS true, regardless of environment.
         * Environment-specific security rules are enforced via StartupChecks.
         * </p>
         */
        public SecurityCorsProperties {
                validateWildcardWithCredentials(allowedOrigins, allowCredentials);
        }

        private static void validateWildcardWithCredentials(
                        List<String> origins,
                        boolean allowCredentials) {

                if (allowCredentials && origins.contains("*")) {
                        throw new IllegalArgumentException("""
                                        Invalid CORS configuration:
                                        allowCredentials=true cannot be combined with wildcard origins.
                                        Browsers block this combination by specification.
                                        """);
                }
        }
}
