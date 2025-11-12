package com.lanny.spring_security_template.infrastructure.metrics;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class PrometheusRegistryTest {

    @Autowired(required = false)
    private PrometheusMeterRegistry prometheusMeterRegistry;

    @Test
    void shouldLoadPrometheusMeterRegistry() {
        assertThat(prometheusMeterRegistry)
            .as("PrometheusMeterRegistry should be auto-configured")
            .isNotNull();
    }
}

