package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account is temporarily locked due to security policies,
 * such as too many failed login attempts.
 */
public class UserLockedException extends RuntimeException {

    public UserLockedException() {
        super("User account is locked");
    }

    public UserLockedException(String message) {
        super(message);
    }
}
