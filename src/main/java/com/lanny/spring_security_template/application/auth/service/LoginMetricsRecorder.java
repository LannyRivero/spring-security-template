package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;

import lombok.RequiredArgsConstructor;

/**
 * Records authentication metrics such as login success and failure.
 *
 * Pure application service — no logging, no MDC, no Spring dependencies.
 * Cross-cutting concerns (logging, auditing) are handled by decorators.
 */
@RequiredArgsConstructor
public class LoginMetricsRecorder {

    private final AuthMetricsService metrics;

    /**
     * Records a successful login metric.
     *
     * @param username the authenticated username
     */
    public void recordSuccess(String username) {
        metrics.recordLoginSuccess();
    }

    /**
     * Records a failed login metric.
     *
     * @param username the attempted username
     * @param reason   brief reason for the failure (e.g. invalid password)
     */
    public void recordFailure(String username, String reason) {
        metrics.recordLoginFailure();
    }
}
