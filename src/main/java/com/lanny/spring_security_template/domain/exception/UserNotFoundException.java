package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a requested user cannot be found in the system.
 * 
 * <p>
 * This exception should be used for scenarios where the application layer
 * requires the existence of a user(e.g., loading profile information,
 * resolving roles, updating account data) and the user record is missing.
 * </p>
 * 
 * <p>
 * Mapperd to <strong>HTTP 404 Not Found</strong> in the web layer.
 * </p>
 * 
 * <p>
 * <strong>Important:</strong> This exception must not be throw from
 * authentication flow; those should to use
 * {@link InvalidCredentialsException} to avoid leaking whether a username
 * exists.
 * </p>
 */

public class UserNotFoundException extends DomainException {
    public static final String CODE = "ERR-USER-404";

    public UserNotFoundException() {
        super(CODE, "User not found");
    }

    public UserNotFoundException(String message) {
        super(CODE, message);
    }
}
