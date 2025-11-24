package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account has been disabled by an administrator.
 */
public class UserDisabledException extends RuntimeException {

    public UserDisabledException() {
        super("User account is disabled");
    }

    public UserDisabledException(String message) {
        super(message);
    }
}
