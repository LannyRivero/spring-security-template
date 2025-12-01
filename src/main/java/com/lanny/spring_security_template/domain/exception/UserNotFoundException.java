package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user is not found in the system.
 */
public final class UserNotFoundException extends DomainException {

    private static final String CODE = "ERR-AUTH-005";
    private static final String KEY  = "auth.user_not_found";
    private static final String DEFAULT_MESSAGE = "User not found";

    /** Default constructor with standard message */
    public UserNotFoundException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Custom message constructor */
    public UserNotFoundException(String message) {
        super(CODE, KEY, message);
    }
}

