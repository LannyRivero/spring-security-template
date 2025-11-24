package com.lanny.spring_security_template.infrastructure.metrics;

import org.springframework.boot.actuate.autoconfigure.metrics.MeterRegistryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

@Configuration
public class PrometheusCommonTagsConfig {

    @Bean
    MeterRegistryCustomizer<PrometheusMeterRegistry> metricsCommonTags() {
        return registry -> registry.config().commonTags(
                "service", "spring-security-template",
                "env", "dev"
        );
    }
}

