package com.lanny.spring_security_template.infrastructure.metrics;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.SecurityBootstrapMetrics;

import io.micrometer.core.instrument.MeterRegistry;
import io.micrometer.core.instrument.Tags;

@Component
@Profile({ "prod", "demo" })
public class SecurityBootstrapMicrometerAdapter
        implements SecurityBootstrapMetrics {

    private static final String METRIC_SUCCESS = "security.bootstrap.success";

    private static final String METRIC_FAILURE = "security.bootstrap.failure";

    private final MeterRegistry registry;

    public SecurityBootstrapMicrometerAdapter(MeterRegistry registry) {
        this.registry = registry;
    }

    @Override
    public void bootstrapSucceeded(int checksCount) {
        registry.counter(
                METRIC_SUCCESS,
                Tags.of("checks", String.valueOf(checksCount))).increment();
    }

    @Override
    public void bootstrapFailed(String checkName) {
        registry.counter(
                METRIC_FAILURE,
                Tags.of("check", checkName)).increment();
    }
}
