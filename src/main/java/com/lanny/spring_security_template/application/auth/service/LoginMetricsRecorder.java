package com.lanny.spring_security_template.application.auth.service;

import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Records authentication metrics such as login success and failure.
 *
 * <p>
 * Provides a decoupled layer to centralize metrics registration,
 * ensuring observability and compliance with security logging standards.
 * </p>
 *
 * <p>
 * Compliant with OWASP ASVS 2.10.1 — “Log all authentication decisions”.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class LoginMetricsRecorder {

    private final AuthMetricsService metrics;

    /**
     * Records a successful login metric and logs the event with context.
     *
     * @param username the authenticated username
     */
    public void recordSuccess(String username) {
        metrics.recordLoginSuccess();
        log.info("[METRIC][LOGIN_SUCCESS] user={} trace={}", username, MDC.get("traceId"));
    }

    /**
     * Records a failed login metric and logs the failure reason.
     *
     * @param username the attempted username
     * @param reason   brief reason for the failure (e.g. invalid password)
     */
    public void recordFailure(String username, String reason) {
        metrics.recordLoginFailure();
        log.warn("[METRIC][LOGIN_FAILURE] user={} trace={} reason={}", username, MDC.get("traceId"), reason);
    }
}
