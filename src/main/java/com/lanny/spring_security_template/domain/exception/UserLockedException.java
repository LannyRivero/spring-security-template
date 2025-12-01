package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account is locked due to security policies.
 */
public final class UserLockedException extends DomainException {

    private static final String CODE = "AUTH-002";
    private static final String KEY = "auth.user_locked";

    public UserLockedException(String message) {
        super(CODE, KEY, message);
    }
}
