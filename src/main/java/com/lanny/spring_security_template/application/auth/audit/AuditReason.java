package com.lanny.spring_security_template.application.auth.audit;

/**
 * Controlled reasons for audit events.
 *
 * Free-text messages are forbidden in audit logs
 * for compliance and security reasons.
 */
public enum AuditReason {

    SUCCESS,
    INVALID_CREDENTIALS,
    TOKEN_EXPIRED,
    ACCESS_DENIED,
    UNKNOWN_FAILURE

}
