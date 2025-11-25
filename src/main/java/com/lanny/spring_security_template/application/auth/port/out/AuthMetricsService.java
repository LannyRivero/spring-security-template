package com.lanny.spring_security_template.application.auth.port.out;

/**
 * Output port for recording authentication-related metrics.
 * Implemented by infrastructure layer (e.g., Prometheus, Micrometer).
 */
public interface AuthMetricsService {
    void recordLoginSuccess();

    void recordLoginFailure();
}
