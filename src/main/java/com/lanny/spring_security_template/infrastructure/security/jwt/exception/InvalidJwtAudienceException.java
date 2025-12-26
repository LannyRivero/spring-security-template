package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * Thrown when a JWT audience claim does not match the expected audience.
 *
 * <p>
 * This indicates that the token was issued for a different service,
 * API or security context and must not be accepted.
 * </p>
 *
 * <p>
 * This exception is intentionally generic and does not expose the
 * actual or expected audience values to prevent information leakage.
 * </p>
 */
public class InvalidJwtAudienceException extends RuntimeException {

    public InvalidJwtAudienceException() {
        super("Invalid JWT audience");
    }
}
