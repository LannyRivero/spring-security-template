package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a Role violates domain formatting or normalization rules.
 */
public final class InvalidRoleException extends DomainException {

    private static final String CODE = "ERR-AUTH-013";
    private static final String KEY  = "auth.invalid_role";
    private static final String DEFAULT_MESSAGE = "Invalid role format";

    /** Default constructor with standard message */
    public InvalidRoleException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Custom message constructor */
    public InvalidRoleException(String message) {
        super(CODE, KEY, message);
    }
}

