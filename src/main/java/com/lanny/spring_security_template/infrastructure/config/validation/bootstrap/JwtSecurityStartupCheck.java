package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.config.validation.SecurityJwtPropertiesValidator;

import org.springframework.stereotype.Component;

/**
 * ============================================================
 * JwtSecurityStartupCheck
 * ============================================================
 *
 * Infrastructure adapter that executes {@link SecurityJwtPropertiesValidator}
 * during application bootstrap.
 *
 * <p>
 * This class integrates the stateless JWT validator into the unified
 * {@link SecurityStartupCheck} bootstrap pipeline.
 * </p>
 *
 * <p>
 * <b>Security guarantee:</b>
 * <ul>
 * <li>Fail-fast on insecure JWT configuration</li>
 * <li>No secrets or token material are logged</li>
 * <li>Executed before any security-sensitive component starts</li>
 * </ul>
 *
 * <p>
 * Enforces ADR-008 (Stateless JWT Authentication).
 * </p>
 */
@Component
public final class JwtSecurityStartupCheck implements SecurityStartupCheck {

    private final SecurityJwtProperties properties;
    private final SecurityJwtPropertiesValidator validator;

    public JwtSecurityStartupCheck(SecurityJwtProperties properties) {
        this.properties = properties;
        this.validator = new SecurityJwtPropertiesValidator();
    }

    @Override
    public String name() {
        return "jwt-properties";
    }

    @Override
    public int getOrder() {
        return -100; // must run early
    }

    @Override
    public void validate() {
        validator.validate(properties);
    }
}
