package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when user credentials (username/password) are invalid.
 */
public final class InvalidCredentialsException extends DomainException {

    private static final String CODE = "AUTH-001";
    private static final String KEY = "auth.invalid_credentials";

    public InvalidCredentialsException(String message) {
        super(CODE, KEY, message);
    }
}
