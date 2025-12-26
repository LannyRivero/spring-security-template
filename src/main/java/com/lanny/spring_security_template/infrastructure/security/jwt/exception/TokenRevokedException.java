package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * Thrown when a JWT access token has been explicitly revoked.
 *
 * <p>
 * This exception is used internally by the JWT authorization filter
 * to signal a revoked token without exposing technical details.
 * </p>
 *
 * <p>
 * It must be mapped to a controlled {@code JwtAuthFailureReason}
 * and never propagated outside the security infrastructure layer.
 * </p>
 */
public final class TokenRevokedException extends RuntimeException {

    public TokenRevokedException() {
        super();
    }

    /**
     * Prevent stack trace generation for control-flow usage.
     */
    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
