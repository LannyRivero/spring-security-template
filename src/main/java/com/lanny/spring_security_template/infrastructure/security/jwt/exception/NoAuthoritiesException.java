package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * ============================================================
 * NoAuthoritiesException
 * ============================================================
 *
 * <p>
 * Thrown when a validated JWT access token contains no roles
 * and no scopes.
 * </p>
 *
 * <h2>Meaning</h2>
 * <p>
 * This exception indicates that the token is:
 * </p>
 * <ul>
 * <li>Cryptographically valid</li>
 * <li>Structurally valid</li>
 * <li>But semantically invalid for authorization</li>
 * </ul>
 *
 * <p>
 * Such tokens must never be accepted for protected endpoints.
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Used as a control-flow exception during authorization</li>
 * <li>Not equivalent to {@code AccessDeniedException}</li>
 * <li>No error message is exposed to avoid information leakage</li>
 * </ul>
 *
 * <h2>Performance considerations</h2>
 * <p>
 * Stack trace generation is intentionally disabled as this
 * exception may occur frequently in authorization filters.
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
