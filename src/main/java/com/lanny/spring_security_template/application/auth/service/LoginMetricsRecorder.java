package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

/**
 * Handles recording authentication metrics in a decoupled way.
 */
@Service
@RequiredArgsConstructor
public class LoginMetricsRecorder {

    private final AuthMetricsService metrics;

    public void recordSuccess() {
        metrics.recordLoginSuccess();
    }

    public void recordFailure() {
        metrics.recordLoginFailure();
    }
}

