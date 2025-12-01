package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when an account has been soft-deleted and must not authenticate.
 */
public final class UserDeletedException extends DomainException {

    private static final String CODE = "AUTH-004";
    private static final String KEY = "auth.user_deleted";

    public UserDeletedException(String message) {
        super(CODE, KEY, message);
    }
}
