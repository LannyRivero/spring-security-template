package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * Thrown when a JWT issuer does not match the configured trusted issuer.
 *
 * <p>
 * This indicates that the token was issued by an untrusted authority
 * or belongs to a different security domain.
 * </p>
 *
 * <p>
 * This exception is intentionally message-free to prevent information
 * leakage in logs or error responses.
 * </p>
 */
public class InvalidJwtIssuerException extends RuntimeException {

    public InvalidJwtIssuerException() {
        super("Invalid JWT issuer");
    }
}
