package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account is disabled by an administrator.
 */
public final class UserDisabledException extends DomainException {

    private static final String CODE = "AUTH-003";
    private static final String KEY = "auth.user_disabled";

    public UserDisabledException(String message) {
        super(CODE, KEY, message);
    }
}
