package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceNoOp;

/**
 * =====================================================================
 * AuthMetricsConfig — Metrics Strategy Configuration
 * =====================================================================
 *
 * Provides a **No-Op fallback** for environments where observability
 * (Micrometer + Prometheus) is not available or not required.
 *
 * Profiles covered:
 * - test → unit tests
 * - integration-test → Testcontainers / integration suites
 * - local → developer laptop
 * - demo → preview environments without Prometheus
 *
 * IMPORTANT:
 * In "prod", a real AuthMetricsService **must** be provided,
 * such as MicrometerPrometheusAuthMetricsService or a Kafka-based auditor.
 *
 * This ensures:
 * - predictable behavior in low-observability environments
 * - full metrics pipeline in production
 * - clean separation of infrastructure concerns
 */
@Configuration
public class AuthMetricsConfig {

    /**
     * Registers a no-op metrics service for environments where
     * metrics should NOT be collected.
     */
    @Bean
    @Profile({ "test", "local", "demo", "integration-test" })
    public AuthMetricsService authMetricsNoOp() {
        return AuthMetricsServiceNoOp.INSTANCE;
    }
}
