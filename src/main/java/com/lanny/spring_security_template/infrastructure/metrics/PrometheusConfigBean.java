package com.lanny.spring_security_template.infrastructure.metrics;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;

/**
 * Forces the registration of Prometheus metrics registry in the Spring context
 * so that /actuator/prometheus endpoint is exposed correctly.
 */
@Configuration
public class PrometheusConfigBean {

    @Bean
    public PrometheusMeterRegistry prometheusMeterRegistry() {
        return new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
    }
}

