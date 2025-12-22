package com.lanny.spring_security_template.infrastructure.config.validation;

import com.lanny.spring_security_template.infrastructure.config.SecurityCorsProperties;

import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Validates CORS configuration for production environments.
 *
 * <p>
 * This validator enforces strict security guarantees and prevents
 * the application from starting with unsafe CORS settings.
 * </p>
 */
@Component
@Profile("prod")
@RequiredArgsConstructor
public class CorsSecurityValidator {

    private final SecurityCorsProperties corsProperties;

    @PostConstruct
    public void validate() {

        List<String> origins = corsProperties.allowedOrigins();

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
