package com.lanny.spring_security_template.application.auth.port.out;

public interface AuthMetricsService {

    void recordLoginSuccess();

    void recordLoginFailure();

    void recordTokenRefresh();

    void recordUserRegistration();

    void recordBruteForceDetected();
}
