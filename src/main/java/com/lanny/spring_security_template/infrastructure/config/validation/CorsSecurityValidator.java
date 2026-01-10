package com.lanny.spring_security_template.infrastructure.config.validation;

import com.lanny.spring_security_template.infrastructure.config.SecurityCorsProperties;

import java.util.List;

/**
 * =====================================================================
 * CorsSecurityValidator
 * =====================================================================
 *
 * Stateless guard that validates CORS configuration for production
 * environments.
 *
 * <p>
 * Prevents insecure CORS setups such as wildcard origins combined
 * with credentialed requests.
 * </p>
 */
public final class CorsSecurityValidator {

    public void validate(SecurityCorsProperties corsProperties) {

        List<String> origins = corsProperties.allowedOrigins();

        if (origins == null || origins.isEmpty()) {
            throw new InvalidSecurityConfigurationException(
                    "CORS allowedOrigins must not be empty in production");
        }

        if (origins.contains("*")) {
            throw new InvalidSecurityConfigurationException(
                    "CORS wildcard '*' is not allowed in production");
        }

        if (corsProperties.allowCredentials() && origins.contains("*")) {
            throw new InvalidSecurityConfigurationException(
                    "CORS allowCredentials=true cannot be used with wildcard origins");
        }
    }
}
