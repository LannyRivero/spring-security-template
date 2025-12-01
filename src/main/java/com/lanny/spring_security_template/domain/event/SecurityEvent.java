package com.lanny.spring_security_template.domain.event;

/**
 * Enumeration of standardized security-related events.
 *
 * <p>
 * Defines all relevant events emitted by the authentication, token,
 * session, and password subsystems. Each constant represents a distinct
 * security lifecycle event, enabling consistent audit logging,
 * observability, SIEM ingestion and compliance with OWASP ASVS logging rules.
 * </p>
 */
public enum SecurityEvent {

    // ----------------------------------------------------------------------
    // AUTHENTICATION EVENTS
    // ----------------------------------------------------------------------

    /** Successful user authentication */
    LOGIN_SUCCESS(Category.AUTH, Severity.INFO,
            "User authenticated successfully"),

    /** Failed user authentication (invalid credentials or unknown user) */
    LOGIN_FAILURE(Category.AUTH, Severity.WARN,
            "Authentication failed: invalid credentials or unknown user"),

    /** Login attempt before outcome is known */
    LOGIN_ATTEMPT(Category.AUTH, Severity.INFO,
            "User attempted to authenticate"),

    // ----------------------------------------------------------------------
    // TOKEN EVENTS
    // ----------------------------------------------------------------------

    /** Successful token refresh */
    TOKEN_REFRESH(Category.TOKEN, Severity.INFO,
            "Refresh token successfully exchanged for new tokens"),

    /** Attempt to refresh token before outcome is known */
    TOKEN_REFRESH_ATTEMPT(Category.TOKEN, Severity.INFO,
            "Attempt to refresh authentication token"),

    /** Token refresh failed */
    TOKEN_REFRESH_FAILED(Category.TOKEN, Severity.WARN,
            "Refresh token invalid or expired"),

    /** Token rotation executed (old revoked, new issued) */
    TOKEN_ROTATED(Category.TOKEN, Severity.INFO,
            "Token rotation completed"),

    /** Token explicitly revoked by logout, rotation, or admin action */
    TOKEN_REVOKED(Category.TOKEN, Severity.INFO,
            "Authentication token revoked"),

    /** New tokens issued (login, refresh, rotation) */
    TOKEN_ISSUED(Category.TOKEN, Severity.INFO,
            "Authentication tokens issued"),

    // ----------------------------------------------------------------------
    // USER ACCOUNT EVENTS
    // ----------------------------------------------------------------------

    /** Account was locked due to brute-force protection */
    USER_LOCKED(Category.USER, Severity.WARN,
            "User account locked due to security policies"),

    /** Successful user registration */
    USER_REGISTERED(Category.USER, Severity.INFO,
            "New user registered"),

    // ----------------------------------------------------------------------
    // PASSWORD EVENTS
    // ----------------------------------------------------------------------

    /** Password successfully changed */
    PASSWORD_CHANGED(Category.PASSWORD, Severity.INFO,
            "Password updated successfully"),

    /** Password change attempt failed */
    PASSWORD_CHANGE_FAILED(Category.PASSWORD, Severity.WARN,
            "Password change failed"),

    /** Attempt to change password before validation */
    PASSWORD_CHANGE_ATTEMPT(Category.PASSWORD, Severity.INFO,
            "User attempted to change password");

    // ----------------------------------------------------------------------
    // INTERNAL FIELDS
    // ----------------------------------------------------------------------

    private final Category category;
    private final Severity severity;
    private final String description;

    SecurityEvent(Category category, Severity severity, String description) {
        this.category = category;
        this.severity = severity;
        this.description = description;
    }

    // ----------------------------------------------------------------------
    // ACCESSORS FOR OBSERVABILITY
    // ----------------------------------------------------------------------

    /** Returns a standardized code for logging and metrics: SEC_EVENTNAME */
    public String code() {
        return "SEC_" + name();
    }

    /** Returns the high-level category of the event */
    public Category category() {
        return category;
    }

    /** Log severity for monitoring systems */
    public Severity severity() {
        return severity;
    }

    /** Human-readable description for logs/SIEM */
    public String description() {
        return description;
    }

    // ----------------------------------------------------------------------
    // ENUMS
    // ----------------------------------------------------------------------

    public enum Category {
        AUTH, TOKEN, USER, PASSWORD
    }

    public enum Severity {
        INFO, WARN, ERROR
    }
}
