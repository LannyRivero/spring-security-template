package com.lanny.spring_security_template.infrastructure.jwt.exception;

/**
 * Exception thrown when a JWT contains no authorities/roles.
 *
 * <p>
 * This indicates a misconfiguration in the token generation process
 * or an invalid token.
 * </p>
 *
 * <p>
 * This is an infrastructure-level exception and must never
 * propagate outside the infrastructure boundary.
 * </p>
 */
public class NoAuthoritiesException extends RuntimeException {

    public NoAuthoritiesException(String message, Throwable cause) {
        super(message, cause);
    }

    public NoAuthoritiesException(String message) {
        super(message);
    }

}
