package com.lanny.spring_security_template.infrastructure.config.validation;

import org.springframework.lang.NonNull;

/**
 * Thrown when a security configuration is invalid or unsafe and
 * the application must fail fast during bootstrap.
 *
 * <p>
 * {@code source} represents a stable logical identifier of the
 * failing security check (used for metrics and diagnostics).
 * </p>
 */
public class InvalidSecurityConfigurationException extends RuntimeException {

    private final String source;

    public InvalidSecurityConfigurationException(
            @NonNull String source,
            @NonNull String message) {

        super(message);
        this.source = source;
    }

    public InvalidSecurityConfigurationException(
            @NonNull String source,
            @NonNull String message,
            @NonNull Throwable cause) {

        super(message, cause);
        this.source = source;
    }

    /**
     * Stable identifier of the failing security check.
     * <p>
     * Examples:
     * <ul>
     * <li>jwt-config</li>
     * <li>cors-policy</li>
     * <li>rsa-key-provider</li>
     * </ul>
     */
    public String getSource() {
        return source;
    }
}
