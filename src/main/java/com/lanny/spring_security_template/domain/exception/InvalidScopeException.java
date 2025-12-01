package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a Scope does not follow the required format:
 *   resource:action
 * Examples:
 *   "simulation:read"
 *   "users:write"
 */
public final class InvalidScopeException extends DomainException {

    private static final String CODE = "ERR-AUTH-014";
    private static final String KEY  = "auth.invalid_scope";
    private static final String DEFAULT_MESSAGE = "Invalid scope format";

    /** Default constructor with standard message */
    public InvalidScopeException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Custom message constructor */
    public InvalidScopeException(String message) {
        super(CODE, KEY, message);
    }
}

