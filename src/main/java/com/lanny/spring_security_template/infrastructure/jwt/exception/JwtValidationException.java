package com.lanny.spring_security_template.infrastructure.jwt.exception;

/**
 * Internal exception for JWT validation failures.
 * Never exposed outside infrastructure.
 */
public final class JwtValidationException extends RuntimeException {

    public JwtValidationException(Throwable cause) {
        super(cause);
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
