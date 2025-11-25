package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Records authentication success/failure metrics.
 */
@Service
@RequiredArgsConstructor
public class LoginMetricsRecorder {

    private final AuthMetricsServiceImpl metrics;

    public void recordSuccess() {
        metrics.recordLoginSuccess();
    }

    public void recordFailure() {
        metrics.recordLoginFailure();
    }
}
