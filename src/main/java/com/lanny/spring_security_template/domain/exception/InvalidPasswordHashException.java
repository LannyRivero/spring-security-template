package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a password hash is syntactically invalid or unsafe
 * according to the domain rules.
 */
public final class InvalidPasswordHashException extends DomainException {

    private static final String CODE = "ERR-AUTH-012";
    private static final String KEY  = "auth.invalid_password_hash";
    private static final String DEFAULT_MESSAGE = "Invalid password hash";

    /** Default constructor with standard message */
    public InvalidPasswordHashException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Custom message constructor */
    public InvalidPasswordHashException(String message) {
        super(CODE, KEY, message);
    }
}

