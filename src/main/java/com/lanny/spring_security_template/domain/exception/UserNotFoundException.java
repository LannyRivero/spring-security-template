package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user is not found in the system.
 */
public final class UserNotFoundException extends DomainException {

    private static final String CODE = "AUTH-005";
    private static final String KEY  = "auth.user_not_found";

    public UserNotFoundException(String message) {
        super(CODE, KEY, message);
    }
}
