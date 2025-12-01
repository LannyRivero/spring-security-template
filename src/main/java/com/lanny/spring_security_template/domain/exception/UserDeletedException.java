package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account has been soft-deleted and must not authenticate.
 */
public final class UserDeletedException extends DomainException {

    private static final String CODE = "ERR-AUTH-004";
    private static final String KEY  = "auth.user_deleted";
    private static final String DEFAULT_MESSAGE = "User account has been deleted";

    /** Default constructor with standard message */
    public UserDeletedException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Custom message constructor */
    public UserDeletedException(String message) {
        super(CODE, KEY, message);
    }
}

