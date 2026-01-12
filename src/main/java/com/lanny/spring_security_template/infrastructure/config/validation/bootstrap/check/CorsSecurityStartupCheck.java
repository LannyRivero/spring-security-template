package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.config.SecurityCorsProperties;
import com.lanny.spring_security_template.infrastructure.config.validation.CorsSecurityValidator;

/**
 * ============================================================
 * CorsSecurityStartupCheck
 * ============================================================
 *
 * Security bootstrap check validating CORS configuration
 * for production environments.
 *
 * <p>
 * This check ensures that Cross-Origin Resource Sharing (CORS)
 * settings do not expose the application to unintended origins
 * or overly permissive access in production.
 * </p>
 *
 * <p>
 * Security rationale:
 * </p>
 * <ul>
 * <li>Overly permissive CORS can bypass authentication controls</li>
 * <li>Wildcard origins are forbidden in production</li>
 * <li>Unsafe defaults must never reach runtime</li>
 * </ul>
 *
 * <p>
 * This check is enforced only when the {@code prod} profile is active.
 * In non-production environments, CORS restrictions are intentionally relaxed
 * to improve developer experience.
 * </p>
 */
@Component
public final class CorsSecurityStartupCheck implements SecurityStartupCheck {

    private static final String CHECK_NAME = "cors";

    private final SecurityCorsProperties corsProperties;
    private final Environment environment;
    private final CorsSecurityValidator validator;

    public CorsSecurityStartupCheck(
            SecurityCorsProperties corsProperties,
            Environment environment) {

        this.corsProperties = corsProperties;
        this.environment = environment;
        this.validator = new CorsSecurityValidator();
    }

    @Override
    public String name() {
        return CHECK_NAME;
    }

    @Override
    public int getOrder() {
        return -60; // after refresh-token checks, before network security
    }

    @Override
    public void validate() {

        if (!isProductionProfileActive()) {
            return;
        }

        validator.validate(corsProperties);
    }

    private boolean isProductionProfileActive() {
        return environment.acceptsProfiles(Profiles.of("prod"));
    }
}
