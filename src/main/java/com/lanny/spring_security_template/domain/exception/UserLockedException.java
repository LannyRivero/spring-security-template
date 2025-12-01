package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account is locked due to security policies
 * (e.g., too many failed login attempts).
 */
public final class UserLockedException extends DomainException {

    private static final String CODE = "ERR-AUTH-002";
    private static final String KEY  = "auth.user_locked";
    private static final String DEFAULT_MESSAGE = "User account is locked";

    /** Default constructor with standard message */
    public UserLockedException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Custom message constructor */
    public UserLockedException(String message) {
        super(CODE, KEY, message);
    }
}

