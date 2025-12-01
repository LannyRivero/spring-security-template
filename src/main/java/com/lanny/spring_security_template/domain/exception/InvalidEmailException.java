package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when an email address is syntactically invalid
 * according to the domain email rules.
 */
public final class InvalidEmailException extends DomainException {

    private static final String CODE = "ERR-AUTH-010";
    private static final String KEY  = "auth.invalid_email";
    private static final String DEFAULT_MESSAGE = "Invalid email address";

    /** Default constructor with standard message. */
    public InvalidEmailException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Allows overriding the default message when needed. */
    public InvalidEmailException(String message) {
        super(CODE, KEY, message);
    }
}

