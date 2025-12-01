package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account is disabled by an administrator.
 */
public final class UserDisabledException extends DomainException {

    private static final String CODE = "ERR-AUTH-003";
    private static final String KEY  = "auth.user_disabled";
    private static final String DEFAULT_MESSAGE = "User account is disabled";

    /** Default constructor with standard message */
    public UserDisabledException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Custom message constructor */
    public UserDisabledException(String message) {
        super(CODE, KEY, message);
    }
}

