package com.lanny.spring_security_template.domain.event;

/**
 * Enumeration of standardized security-related events.
 *
 * <p>
 * Defines all relevant events emitted by the authentication and session
 * subsystems.
 * Each constant represents a distinct security lifecycle event, ensuring
 * uniform
 * audit logging and observability integration across the platform.
 * </p>
 *
 * <p>
 * <strong>Aligned with OWASP ASVS:</strong>
 * </p>
 * <ul>
 * <li>2.10.1 – Log all authentication decisions</li>
 * <li>2.10.3 – Log all session management events</li>
 * <li>2.10.4 – Include enough context for traceability</li>
 * <li>2.8.x – Password change and recovery flows</li>
 * </ul>
 *
 * <p>
 * <strong>Typical usage:</strong>
 * </p>
 * 
 * <pre>{@code
 * auditEventPublisher.publishAuthEvent(
 *         SecurityEvent.LOGIN_SUCCESS.name(),
 *         username,
 *         clockProvider.now(),
 *         "User authenticated successfully");
 * }</pre>
 */
public enum SecurityEvent {

    /** Successful user authentication */
    LOGIN_SUCCESS,

    /** Failed user authentication (invalid credentials or unknown user) */
    LOGIN_FAILURE,

    LOGIN_ATTEMPT,

    /** Token successfully refreshed */
    TOKEN_REFRESH,

    /** Token rotation occurred (old token revoked, new issued) */
    TOKEN_ROTATED,

    /** Token explicitly revoked (logout, rotation, admin action) */
    TOKEN_REVOKED,

    /** Token(s) issued (login, refresh, rotation) */
    TOKEN_ISSUED,

    /** User account temporarily locked due to brute-force protection */
    USER_LOCKED,

    USER_REGISTERED,

    /** Password successfully changed by user */
    PASSWORD_CHANGED,

    /** Password change failed (invalid current password or weak new password) */
    PASSWORD_CHANGE_FAILED;

    /**
     * Returns a standardized code for external logging or metrics.
     * 
     * @return code in format SEC_EVENTNAME (e.g. SEC_LOGIN_SUCCESS)
     */
    public String code() {
        return "SEC_" + name();
    }
}
