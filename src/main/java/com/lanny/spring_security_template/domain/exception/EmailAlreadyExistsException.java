package com.lanny.spring_security_template.domain.exception;

/**
 * Exception thrown when attempting to register or update a user
 * with an email address that is already in use.
 */
public final class EmailAlreadyExistsException extends DomainException {

    public EmailAlreadyExistsException(String message) {
        super("ERR-USER-002", "user.email.alreadyExists", message);
    }
}
