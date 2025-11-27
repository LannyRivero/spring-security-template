package com.lanny.spring_security_template.application.auth.port.out;

/**
 * Central interface for recording authentication and authorization metrics.
 *
 * <p>
 * All methods increment counters used for observability, alerting, and security
 * analysis.
 * Implementations are typically backed by Micrometer and exposed via Actuator
 * (/actuator/prometheus).
 * </p>
 *
 * <p>
 * Metrics naming follows the convention:
 * <code>auth.&lt;event&gt;.total</code>
 * </p>
 */
public interface AuthMetricsService {

    /** Increment on successful login attempts. */
    void recordLoginSuccess();

    /** Increment on failed login attempts (invalid credentials, user not found). */
    void recordLoginFailure();

    /** Increment when an access token is successfully refreshed. */
    void recordTokenRefresh();

    /** Increment when a new user account is registered. */
    void recordUserRegistration();

    /** Increment when brute-force behavior is detected and temporarily blocked. */
    void recordBruteForceDetected();

    /**
     * Increment when an active session or refresh token is revoked manually or by
     * policy.
     */
    void recordSessionRevoked();

    /**
     * Increment when a token rotation process fails (unexpected exception or
     * validation error).
     */
    void recordRotationFailed();

    /**
     * Increment when a user is temporarily locked after too many failed attempts.
     */
    void recordUserLocked();

    /** Increment when a refresh token is re-used (possible replay attack). */
    void recordRefreshReused();

    /** Increment when a user successfully changes their password. */
    void recordPasswordChange();
}
