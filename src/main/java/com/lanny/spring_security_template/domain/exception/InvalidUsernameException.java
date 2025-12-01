package com.lanny.spring_security_template.domain.exception;

public final class InvalidUsernameException extends DomainException {

    private static final String CODE = "AUTH-011";
    private static final String KEY = "auth.invalid_username";

    public InvalidUsernameException(String message) {
        super(CODE, KEY, message);
    }
}
