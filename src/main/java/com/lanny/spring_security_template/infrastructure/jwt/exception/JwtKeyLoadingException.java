package com.lanny.spring_security_template.infrastructure.jwt.exception;

/**
 * Exception thrown when an RSA key cannot be loaded or parsed.
 *
 * <p>
 * This is an infrastructure-level exception and must never
 * propagate outside the infrastructure boundary.
 * </p>
 */
public final class JwtKeyLoadingException extends RuntimeException {

    public JwtKeyLoadingException(String message) {
        super(message);
    }

    public JwtKeyLoadingException(String message, Throwable cause) {
        super(message, cause);
    }
}
