package com.lanny.spring_security_template.infrastructure.metrics;

public interface AuthMetricsService {

    void recordLoginSuccess();

    void recordLoginFailure();

    void recordTokenRefresh();

    void recordUserRegistration();

    void recordBruteForceDetected();
}
