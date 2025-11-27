package com.lanny.spring_security_template.infrastructure.metrics;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;

/**
 * No-op (no operation) implementation of {@link AuthMetricsService}.
 *
 * <p>
 * Used in testing or non-observability profiles (e.g., "test", "local").
 * All metric methods are empty to avoid any dependency on Micrometer or
 * MeterRegistry.
 * </p>
 *
 * <p>
 * This ensures that all application components depending on
 * {@link AuthMetricsService} can operate without side effects
 * even when observability is disabled.
 * </p>
 *
 * <p>
 * Typical usage:
 * 
 * <pre>
 * {@code
 * @Bean
 * @Profile("test")
 * public AuthMetricsService authMetricsService() {
 *     return AuthMetricsServiceNoOp.INSTANCE;
 * }
 * }
 * </pre>
 * </p>
 */
public final class AuthMetricsServiceNoOp implements AuthMetricsService {

    /** Singleton instance — safe for reuse across the application. */
    public static final AuthMetricsServiceNoOp INSTANCE = new AuthMetricsServiceNoOp();

    private AuthMetricsServiceNoOp() {
        // private constructor to enforce singleton
    }

    @Override public void recordLoginSuccess() {}
    @Override public void recordLoginFailure() {}
    @Override public void recordTokenRefresh() {}
    @Override public void recordUserRegistration() {}
    @Override public void recordBruteForceDetected() {}
    @Override public void recordSessionRevoked() {}
    @Override public void recordRotationFailed() {}
    @Override public void recordUserLocked() {}
    @Override public void recordRefreshReused() {}
    @Override public void recordPasswordChange() {}
}

