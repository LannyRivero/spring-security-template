package com.lanny.spring_security_template.domain.exception;

public final class InvalidScopeException extends DomainException {

    private static final String CODE = "AUTH-014";
    private static final String KEY = "auth.invalid_scope";

    public InvalidScopeException(String message) {
        super(CODE, KEY, message);
    }
}
