package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import com.lanny.spring_security_template.infrastructure.config.SecurityCorsProperties;
import com.lanny.spring_security_template.infrastructure.config.validation.CorsSecurityValidator;
import com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.SecurityStartupCheck;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * ============================================================
 * CorsSecurityStartupCheck
 * ============================================================
 *
 * Security bootstrap check validating CORS configuration
 * for production environments.
 */
@Component
public final class CorsSecurityStartupCheck implements SecurityStartupCheck {

    private static final String CHECK_NAME = "cors";
    private static final Set<String> PROD_PROFILES = Set.of("prod");

    private final SecurityCorsProperties corsProperties;
    private final Environment environment;
    private final CorsSecurityValidator guard;

    public CorsSecurityStartupCheck(
            SecurityCorsProperties corsProperties,
            Environment environment) {

        this.corsProperties = corsProperties;
        this.environment = environment;
        this.guard = new CorsSecurityValidator();
    }

    @Override
    public String name() {
        return CHECK_NAME;
    }

    @Override
    public int getOrder() {
        return -60; // after refresh-token, before network
    }

    @Override
    public void validate() {

        if (!isProductionProfileActive()) {
            return;
        }

        guard.validate(corsProperties);
    }

    private boolean isProductionProfileActive() {
        for (String profile : environment.getActiveProfiles()) {
            if (PROD_PROFILES.contains(profile)) {
                return true;
            }
        }
        return false;
    }
}
