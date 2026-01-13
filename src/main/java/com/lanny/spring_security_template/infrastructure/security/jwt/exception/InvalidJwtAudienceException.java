package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * ============================================================
 * InvalidJwtAudienceException
 * ============================================================
 *
 * <p>
 * Thrown when a JWT {@code aud} (audience) claim does not match
 * the expected audience configured for the current security context.
 * </p>
 *
 * <h2>Security implications</h2>
 * <ul>
 * <li>Indicates token misuse across services or APIs</li>
 * <li>Prevents accepting tokens issued for a different audience</li>
 * <li>Enforces strict security boundaries in multi-service systems</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Does not expose actual or expected audience values</li>
 * <li>Intentionally generic to prevent information leakage</li>
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
public class InvalidJwtAudienceException extends RuntimeException {

    public InvalidJwtAudienceException() {
        super("Invalid JWT audience");
    }
}
