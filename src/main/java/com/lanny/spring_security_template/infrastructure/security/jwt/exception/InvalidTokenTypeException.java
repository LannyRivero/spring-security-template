package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * Thrown when a JWT token is not an access token.
 *
 * <p>
 * Used to explicitly reject refresh tokens or unsupported
 * token types at the authorization layer.
 * </p>
 */
public final class InvalidTokenTypeException extends RuntimeException {

    public InvalidTokenTypeException() {
        super();
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
