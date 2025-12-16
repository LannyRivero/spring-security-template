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

                /** Allowed origin URLs (e.g. https://app.company.com) */
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
         * Enforces strict CORS rules for enterprise environments.
         */
        public SecurityCorsProperties {
                validateWildcardOriginWithCredentials(allowedOrigins, allowCredentials);
                validateWildcardOriginInRestrictedProfiles(allowedOrigins);
        }

        private static void validateWildcardOriginWithCredentials(
                        List<String> allowedOrigins,
                        boolean allowCredentials) {

                if (allowCredentials && allowedOrigins.contains("*")) {
                        throw new IllegalArgumentException("""
                                        Invalid CORS configuration:
                                        allowCredentials=true cannot be combined with allowedOrigins="*".
                                        Browsers block this combination for security reasons.
                                        """);
                }
        }

        private static void validateWildcardOriginInRestrictedProfiles(
                        List<String> allowedOrigins) {

                String activeProfiles = resolveActiveProfiles();

                if (activeProfiles.contains("prod")
                                || activeProfiles.contains("stage")
                                || activeProfiles.contains("qa")) {

                        if (allowedOrigins.contains("*")) {
                                throw new IllegalStateException("""
                                                SECURITY ERROR:
                                                Wildcard CORS origins ("*") are forbidden in restricted environments.
                                                You MUST explicitly configure trusted origins, for example:
                                                  - https://dashboard.company.com
                                                  - https://app.company.com
                                                """);
                        }
                }
        }

        /**
         * Resolves active Spring profiles in a container-safe way.
         *
         * Priority:
         * 1. SPRING_PROFILES_ACTIVE env var
         * 2. spring.profiles.active JVM property
         * 3. "dev" fallback
         */
        private static String resolveActiveProfiles() {
                String envProfiles = System.getenv("SPRING_PROFILES_ACTIVE");
                if (envProfiles != null && !envProfiles.isBlank()) {
                        return envProfiles.toLowerCase();
                }

                String sysProfiles = System.getProperty("spring.profiles.active");
                if (sysProfiles != null && !sysProfiles.isBlank()) {
                        return sysProfiles.toLowerCase();
                }

                return "dev";
        }
}
