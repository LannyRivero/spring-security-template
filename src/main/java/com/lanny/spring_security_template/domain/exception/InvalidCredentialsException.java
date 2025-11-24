package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when authentication fails due to invalid username or password.
 * This is a pure domain exception and should be mapped to a 401 Unauthorized
 * by the infrastructure layer.
 */
public class InvalidCredentialsException extends RuntimeException {

    public InvalidCredentialsException() {
        super("Invalid username or password");
    }

    public InvalidCredentialsException(String message) {
        super(message);
    }
}
