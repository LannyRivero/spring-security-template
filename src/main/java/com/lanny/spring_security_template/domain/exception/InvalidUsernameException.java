package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a Username violates domain validation rules.
 *
 * Examples:
 * - Too short / too long
 * - Contains invalid characters
 * - Starts/ends with '.'
 * - Contains '..'
 */
public final class InvalidUsernameException extends DomainException {

    private static final String CODE = "ERR-AUTH-011";
    private static final String KEY  = "auth.invalid_username";
    private static final String DEFAULT_MESSAGE = "Invalid username";

    /** Default constructor with standard message */
    public InvalidUsernameException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Custom message constructor */
    public InvalidUsernameException(String message) {
        super(CODE, KEY, message);
    }
}

