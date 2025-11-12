package com.lanny.spring_security_template.infrastructure.metrics;

import org.springframework.stereotype.Component;

import io.micrometer.core.instrument.MeterRegistry;

@Component
public class AuthMetricsService {

    private final MeterRegistry registry;

    public AuthMetricsService(MeterRegistry registry) {
        this.registry = registry;
    }

    public void recordLoginSuccess(String username) {
        registry.counter("auth.login.success.total").increment();
        registry.counter("auth.login.success.by_user", "username", username).increment();
    }

    public void recordLoginFailure(String username) {
        registry.counter("auth.login.failure.total").increment();
        registry.counter("auth.login.failure.by_user", "username", username).increment();
    }

    public void recordTokenRotation() {
        registry.counter("auth.token.rotation.total").increment();
    }
}

