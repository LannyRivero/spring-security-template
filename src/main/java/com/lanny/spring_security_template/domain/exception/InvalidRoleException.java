package com.lanny.spring_security_template.domain.exception;

public final class InvalidRoleException extends DomainException {

    private static final String CODE = "AUTH-013";
    private static final String KEY = "auth.invalid_role";

    public InvalidRoleException(String message) {
        super(CODE, KEY, message);
    }
}
