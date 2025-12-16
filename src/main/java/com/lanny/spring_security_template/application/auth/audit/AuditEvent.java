package com.lanny.spring_security_template.application.auth.audit;

/**
 * Enumerates all security-relevant audit events.
 *
 * These events are part of the application language
 * and must be stable and auditable.
 */
public enum AuditEvent {

    AUTH_LOGIN,
    AUTH_LOGIN_FAILURE,
    AUTH_REFRESH,
    PASSWORD_CHANGE

}

