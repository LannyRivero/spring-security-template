package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * ============================================================
 * InvalidJwtIssuerException
 * ============================================================
 *
 * <p>
 * Thrown when a JWT {@code iss} (issuer) claim does not match
 * the configured trusted issuer for the current security domain.
 * </p>
 *
 * <h2>Security implications</h2>
 * <ul>
 * <li>Indicates the token was issued by an untrusted authority</li>
 * <li>Prevents accepting tokens from foreign or misconfigured issuers</li>
 * <li>Enforces strict trust boundaries in multi-issuer environments</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Does not expose actual or expected issuer values</li>
 * <li>Message is intentionally generic to prevent information leakage</li>
 * <li>Used exclusively within JWT validation infrastructure</li>
 * </ul>
 *
 * <h2>Handling</h2>
 * <p>
 * This exception is expected to be translated by the security
 * error handling layer into a standardized authentication failure
 * response (e.g. HTTP 401).
 * </p>
 */
public class InvalidJwtIssuerException extends RuntimeException {

    public InvalidJwtIssuerException() {
        super("Invalid JWT issuer");
    }
}
