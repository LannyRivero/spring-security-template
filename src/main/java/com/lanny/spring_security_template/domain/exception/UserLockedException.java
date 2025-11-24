package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account is locked due to security policies,
 * typically after too many failed login attempts.
 *
 * <p>Mapped to <strong>HTTP 403 Forbidden</strong>.</p>
 */
public class UserLockedException extends DomainException {

    public static final String CODE = "ERR-AUTH-002";

    public UserLockedException() {
        super(CODE, "User account is locked");
    }

    public UserLockedException(String message) {
        super(CODE, message);
    }
}

