package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.NotEmpty;
import java.util.List;

/**
 * Strongly-typed configuration for Cross-Origin Resource Sharing (CORS).
 *
 * <p>
 * Properties are mapped from <code>security.cors.*</code> and allow
 * environment-specific customization without modifying code.
 * This configuration is consumed by WebCommonConfig, where CORS rules
 * are applied globally.
 * </p>
 *
 * <h2>Key Features</h2>
 * <ul>
 * <li>Supports environment-specific CORS policies.</li>
 * <li>Allows fine-grained control over allowed origins, methods, and
 * headers.</li>
 * <li>Compatible with strict security defaults for production
 * environments.</li>
 * </ul>
 *
 * <h2>Important Security Notes</h2>
 * <ul>
 * <li>If <b>allowCredentials = true</b>, wildcard origins (<code>*</code>) are
 * not permitted by browsers.</li>
 * <li>Use allow-origin-patterns instead when dynamic or wildcard origins are
 * required.</li>
 * </ul>
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

                /** Headers exposed to the browser (e.g. X-Correlation-Id) */
                @DefaultValue({ "X-Correlation-Id" }) List<String> exposedHeaders,

                /** Whether cookies / Authorization headers can be sent cross-origin */
                @DefaultValue("false") boolean allowCredentials){
        /**
         * Compact constructor for validation at bind-time.
         *
         * <p>
         * Prevents invalid CORS settings:
         * <ul>
         * <li>If allowCredentials=true, then wildcard origin "*" is forbidden.</li>
         * </ul>
         * This is enforced because browsers will reject such a configuration,
         * leaving developers confused if not validated early.
         * </p>
         */
        public SecurityCorsProperties {
                validateWildcardOriginWithCredentials(allowedOrigins, allowCredentials);
        }

        private static void validateWildcardOriginWithCredentials(List<String> allowedOrigins,
                        boolean allowCredentials) {

                if (allowCredentials && allowedOrigins.contains("*")) {
                        throw new IllegalArgumentException(
                                        """
                                                        Invalid CORS configuration: allowCredentials=true cannot be combined with allowedOrigins="*".
                                                        Browsers reject this configuration for security reasons.
                                                        Please set explicit origins instead of wildcard.
                                                        """);
                }
        }
}
