package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import org.springframework.core.Ordered;

/**
 * A startup check executed during application bootstrap to validate
 * production-grade security configuration.
 *
 * <p>
 * Implementations must:
 * <ul>
 * <li>Fail fast by throwing a RuntimeException (typically
 * InvalidSecurityConfigurationException)</li>
 * <li>Never log or expose secrets, tokens, or raw key material</li>
 * <li>Be deterministic and side-effect free</li>
 * </ul>
 */
public interface SecurityStartupCheck extends Ordered {

    /**
     * A human-readable check name used for diagnostics (no secrets).
     */
    String name();

    /**
     * Executes validation and throws if configuration is invalid or unsafe.
     */
    void validate();

    /**
     * Default order is "middle". Override if you need strict precedence.
     */
    @Override
    default int getOrder() {
        return 0;
    }
}
