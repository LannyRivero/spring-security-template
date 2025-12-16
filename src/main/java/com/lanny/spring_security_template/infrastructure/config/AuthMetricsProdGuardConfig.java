package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;

/**
 * =====================================================================
 * AuthMetricsProdGuardConfig — Production Safety Guard
 * =====================================================================
 *
 * FAIL-FAST configuration for production environments.
 *
 * In banking-grade systems, metrics and observability are NOT optional
 * in production. If no AuthMetricsService implementation is explicitly
 * provided, application startup must fail with a clear error.
 *
 * This guard prevents:
 * - accidental deployments without metrics
 * - silent fallback to No-Op implementations
 * - loss of observability in prod
 */
@Configuration
@Profile("prod")
public class AuthMetricsProdGuardConfig {

    @Bean
    public AuthMetricsService authMetricsServiceMissingGuard() {
        throw new IllegalStateException(
                "FATAL: No AuthMetricsService implementation configured for 'prod' profile. " +
                        "Production requires an explicit metrics implementation.");
    }
}
