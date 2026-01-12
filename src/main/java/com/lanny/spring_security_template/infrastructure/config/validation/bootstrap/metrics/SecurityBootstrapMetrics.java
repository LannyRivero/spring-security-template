package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.metrics;

/**
 * Metrics emitted during security bootstrap validation.
 *
 * <p>
 * Implementations must be safe to call during application startup.
 */
public interface SecurityBootstrapMetrics {

    /**
     * Called when all security startup checks pass successfully.
     */
    void bootstrapSucceeded(int checksCount);

    /**
     * Called when a security startup check fails.
     *
     * @param checkName logical name of the failed check (no secrets)
     */
    void bootstrapFailed(String checkName);
}
