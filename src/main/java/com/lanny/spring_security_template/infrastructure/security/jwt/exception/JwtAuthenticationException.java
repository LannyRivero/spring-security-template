package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * AuthenticationException representing an invalid or rejected JWT.
 *
 * Used to ensure JWT validation failures are handled as authentication
 * errors (401) and never as internal server errors (500).
 */
public class JwtAuthenticationException extends AuthenticationException {

    public JwtAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    public JwtAuthenticationException(String message) {
        super(message);
    }
}
