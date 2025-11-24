package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user attempts to authenticate with invalid credentials.
 * 
 * <p>Mapped to <strong>HTTP 401 Unauthorized</strong> in the web layer.
 * Should never leak details such as whether the username exists.</p>
 */
public class InvalidCredentialsException extends DomainException {

    public static final String CODE = "ERR-AUTH-001";

    public InvalidCredentialsException() {
        super(CODE, "Invalid username or password");
    }

    public InvalidCredentialsException(String message) {
        super(CODE, message);
    }
}

