package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user provides invalid login credentials.
 * Domain-level exception used in authentication use cases.
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
