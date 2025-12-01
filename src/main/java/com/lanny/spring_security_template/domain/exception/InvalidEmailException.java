package com.lanny.spring_security_template.domain.exception;

public final class InvalidEmailException extends DomainException {

    private static final String CODE = "AUTH-010";
    private static final String KEY = "auth.invalid_email";

    public InvalidEmailException(String message) {
        super(CODE, KEY, message);
    }
}
