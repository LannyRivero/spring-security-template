package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.config.validation.SecurityJwtPropertiesValidator;
import com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.SecurityStartupCheck;

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
 * This adapter integrates the stateless JWT configuration validator
 * into the unified {@link SecurityStartupCheck} bootstrap pipeline.
 * </p>
 *
 * <p>
 * <b>Security guarantees</b>:
 * <ul>
 * <li>Fail-fast on insecure or inconsistent JWT configuration</li>
 * <li>No secrets, tokens, or cryptographic material are logged</li>
 * <li>Executed before any security-sensitive component is initialized</li>
 * </ul>
 *
 * <p>
 * Enforces ADR-008: Stateless JWT Authentication over Session-Based.
 * </p>
 */
@Component
public final class JwtSecurityStartupCheck implements SecurityStartupCheck {

    private static final String CHECK_NAME = "jwt-properties";

    private final SecurityJwtProperties properties;
    private final SecurityJwtPropertiesValidator validator;

    public JwtSecurityStartupCheck(SecurityJwtProperties properties) {
        this.properties = properties;
        this.validator = new SecurityJwtPropertiesValidator();
    }

    @Override
    public String name() {
        return CHECK_NAME;
    }

    /**
     * JWT configuration must be validated very early, as it affects:
     * <ul>
     * <li>Token issuance</li>
     * <li>Token verification</li>
     * <li>Key material loading</li>
     * <li>Downstream security components</li>
     * </ul>
     */
    @Override
    public int getOrder() {
        return -100;
    }

    @Override
    public void validate() {
        validator.validate(properties);
    }
}
