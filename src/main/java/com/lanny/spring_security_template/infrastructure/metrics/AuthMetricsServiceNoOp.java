package com.lanny.spring_security_template.infrastructure.metrics;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;

/**
 * No-op implementation used in tests.
 */
public final class AuthMetricsServiceNoOp implements AuthMetricsService {

    public static final AuthMetricsServiceNoOp INSTANCE = new AuthMetricsServiceNoOp();

    private AuthMetricsServiceNoOp() {}

    @Override public void recordLoginSuccess() {}
    @Override public void recordLoginFailure() {}
    @Override public void recordTokenRefresh() {}
    @Override public void recordUserRegistration() {}
    @Override public void recordBruteForceDetected() {}
}

