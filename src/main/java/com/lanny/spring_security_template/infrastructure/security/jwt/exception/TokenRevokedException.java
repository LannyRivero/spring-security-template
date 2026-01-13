package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * ============================================================
 * TokenRevokedException
 * ============================================================
 *
 * <p>
 * Thrown when a JWT access token has been explicitly revoked.
 * </p>
 *
 * <h2>Meaning</h2>
 * <p>
 * Indicates that the token was previously valid but has been
 * invalidated by the system (e.g. logout, refresh rotation,
 * security compromise).
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Used exclusively within the security infrastructure layer</li>
 * <li>Must be caught and mapped to a controlled failure reason</li>
 * <li>Must never propagate to application or API layers</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>No technical details are exposed</li>
 * <li>No distinction is leaked between revocation mechanisms</li>
 * </ul>
 *
 * <h2>Performance considerations</h2>
 * <p>
 * Stack trace generation is intentionally disabled as this
 * exception may occur frequently under normal operation.
 * </p>
 */
public final class TokenRevokedException extends RuntimeException {

    public TokenRevokedException() {
        super();
    }

    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
