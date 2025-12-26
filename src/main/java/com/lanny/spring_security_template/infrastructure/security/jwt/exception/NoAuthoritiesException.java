package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * Thrown when a validated JWT contains no roles or scopes.
 *
 * <p>
 * This indicates a malformed or non-compliant access token,
 * which must never be accepted for authorization.
 * </p>
 */
public final class NoAuthoritiesException extends RuntimeException {

    public NoAuthoritiesException() {
        super();
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
