package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a user account has been soft-deleted and must no longer
 * be allowed to authenticate or perform operations.
 *
 * <p>Mapped to <strong>HTTP 403 Forbidden</strong>.</p>
 */
public class UserDeletedException extends DomainException {

    public static final String CODE = "ERR-AUTH-004";

    public UserDeletedException() {
        super(CODE, "User account has been deleted");
    }

    public UserDeletedException(String message) {
        super(CODE, message);
    }
}

