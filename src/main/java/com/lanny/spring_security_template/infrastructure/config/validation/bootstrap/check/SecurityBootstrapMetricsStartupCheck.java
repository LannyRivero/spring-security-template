package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;
import com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.metrics.NoOpSecurityBootstrapMetrics;
import com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.metrics.SecurityBootstrapMetrics;

/**
 * Startup check that enforces mandatory security observability
 * in production environments.
 *
 * <p>
 * In production, the application must not start if a
 * {@link NoOpSecurityBootstrapMetrics} implementation is active.
 * </p>
 */
@Component
@Profile("prod")
public final class SecurityBootstrapMetricsStartupCheck implements SecurityStartupCheck {

    private static final String SOURCE = "security-bootstrap-metrics";

    private final SecurityBootstrapMetrics metrics;

    public SecurityBootstrapMetricsStartupCheck(SecurityBootstrapMetrics metrics) {
        this.metrics = metrics;
    }

    @Override
    public String name() {
        return "Security bootstrap metrics enforcement";
    }

    @Override
    public void validate() {
        if (metrics instanceof NoOpSecurityBootstrapMetrics) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "Security bootstrap metrics are disabled in production. " +
                            "Observability is mandatory for production deployments. " +
                            "Configure a real SecurityBootstrapMetrics implementation.");
        }
    }
}
