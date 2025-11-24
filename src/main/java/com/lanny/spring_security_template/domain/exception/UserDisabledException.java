package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account has been permanently disabled
 * by an administrator or security policy.
 *
 * <p>Mapped to <strong>HTTP 403 Forbidden</strong>.</p>
 */
public class UserDisabledException extends DomainException {

    public static final String CODE = "ERR-AUTH-003";

    public UserDisabledException() {
        super(CODE, "User account is disabled");
    }

    public UserDisabledException(String message) {
        super(CODE, message);
    }
}

