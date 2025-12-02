package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotEmpty;
import java.util.List;

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

                /** Allowed origin URLs (e.g. http://localhost:3000) */
                @NotEmpty @DefaultValue( {
                                "*" }) List<String> allowedOrigins,

                /** Allowed HTTP methods for cross-origin requests */
                @NotEmpty @DefaultValue({ "GET", "POST", "PUT", "DELETE", "OPTIONS" }) List<String> allowedMethods,

                /** Allowed headers received in CORS requests */
                @NotEmpty @DefaultValue({ "Authorization", "Content-Type" }) List<String> allowedHeaders,

                /** Headers exposed to the browser (e.g., X-Correlation-Id) */
                @DefaultValue({ "X-Correlation-Id" }) List<String> exposedHeaders,

                /** Whether cookies / Authorization headers can be sent cross-origin */
                @DefaultValue("false") boolean allowCredentials){

        /**
         * Compact constructor for validation at bind-time.
         * Enforces:
         * - no "*" + allowCredentials=true (browser restriction)
         * - no "*" in production environments (security rule)
         */
        public SecurityCorsProperties {
                validateWildcardOriginWithCredentials(allowedOrigins, allowCredentials);
                validateWildcardOriginInProduction(allowedOrigins);
        }

        private static void validateWildcardOriginWithCredentials(
                        List<String> allowedOrigins,
                        boolean allowCredentials) {
                if (allowCredentials && allowedOrigins.contains("*")) {
                        throw new IllegalArgumentException("""
                                        Invalid CORS configuration:
                                        allowCredentials=true cannot be combined with allowedOrigins="*".
                                        Browsers block this for security reasons.
                                        """);
                }
        }

        private static void validateWildcardOriginInProduction(List<String> allowedOrigins) {

                String profile = System.getProperty("spring.profiles.active", "dev");

                if (profile.equalsIgnoreCase("prod")
                                || profile.equalsIgnoreCase("stage")
                                || profile.equalsIgnoreCase("qa")) {

                        if (allowedOrigins.contains("*")) {
                                throw new IllegalStateException("""
                                                SECURITY ERROR: Wildcard CORS origins ("*") are forbidden in production.
                                                You MUST explicitly define trusted origins, e.g.:
                                                - https://dashboard.company.com
                                                - https://app.company.com
                                                """);
                        }
                }
        }
}
