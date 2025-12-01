package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when user credentials (username/password) are invalid.
 */
public final class InvalidCredentialsException extends DomainException {

    private static final String CODE = "ERR-AUTH-001";
    private static final String KEY  = "auth.invalid_credentials";
    private static final String DEFAULT_MESSAGE = "Invalid username or password";

    /** Default constructor required by tests and domain logic */
    public InvalidCredentialsException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Explicit custom message constructor */
    public InvalidCredentialsException(String message) {
        super(CODE, KEY, message);
    }
}

