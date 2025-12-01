package com.lanny.spring_security_template.domain.exception;

public final class InvalidPasswordHashException extends DomainException {

    private static final String CODE = "AUTH-012";
    private static final String KEY = "auth.invalid_password_hash";

    public InvalidPasswordHashException(String message) {
        super(CODE, KEY, message);
    }
}
