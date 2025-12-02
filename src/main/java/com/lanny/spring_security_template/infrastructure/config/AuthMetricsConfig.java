package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceNoOp;

/**
 * Metrics configuration providing fallback No-Op implementation for tests
 * and enviroments where observability is disabled.
 * 
 */
@Configuration
public class AuthMetricsConfig {

    /**
     * Provides a no-Op metrics implementation for unit tests and enviroments
     * wjthout Micrometer/Prometheus.
     */
    @Bean
    @Profile({ "test", "local", "demo" })
    public AuthMetricsService authMetricsNoOp() {
        return AuthMetricsServiceNoOp.INSTANCE;

    }
}
