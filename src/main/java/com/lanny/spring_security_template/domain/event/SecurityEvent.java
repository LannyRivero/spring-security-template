package com.lanny.spring_security_template.domain.event;

/**
 * Enumeration of standardized security-related events.
 *
 * <p>
 * This enum defines all relevant events that can be emitted by
 * {@link com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher}
 * across authentication, authorization, and session management flows.
 * </p>
 *
 * <p>
 * Each constant represents a unique event type used for:
 * <ul>
 * <li>Security audits</li>
 * <li>Monitoring and alerting (Prometheus, Loki, ELK)</li>
 * <li>Event streaming (Kafka, Webhooks, SIEM)</li>
 * </ul>
 * </p>
 *
 * <p>
 * Following <strong>OWASP ASVS</strong> recommendations:
 * <ul>
 * <li>2.10.1 – Log all authentication decisions</li>
 * <li>2.10.3 – Log all session management events</li>
 * <li>2.10.4 – Include enough context for traceability</li>
 * </ul>
 * </p>
 *
 * <p>
 * Typical usage:
 * 
 * <pre>{@code
 * auditEventPublisher.publishAuthEvent(
 *         SecurityEvent.LOGIN_FAILURE.name(),
 *         username,
 *         clockProvider.now(),
 *         "Invalid credentials");
 * }</pre>
 * </p>
 */
public enum SecurityEvent {

    /** Successful user authentication */
    LOGIN_SUCCESS,

    /** Failed user authentication (invalid credentials or unknown user) */
    LOGIN_FAILURE,

    /** Successful token refresh */
    TOKEN_REFRESH,

    /** Token rotation occurred (old token revoked, new issued) */
    TOKEN_ROTATED,

    /** Token explicitly revoked (logout, rotation, admin action) */
    TOKEN_REVOKED,
    
    /** Token(s) issued (login, refresh, rotation) */
    TOKEN_ISSUED,

    /** User account temporarily locked (e.g., due to brute-force protection) */
    USER_LOCKED,

    /** User successfully logged in */
    USER_LOGGED_IN
}
