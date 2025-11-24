package com.lanny.spring_security_template.domain.exception;

/**
 * Base class for all domain-level exceptions.
 *
 * <p>
 * This class exists to allow grouped handling of all domain rules
 * in the infrastructure/web layer (e.g. GlobalExceptionHandler),
 * while keeping individual exception types explicit and meaningful.
 * </p>
 */
public abstract class DomainException extends RuntimeException {

    /** Machine-readable internal error code (e.g., ERR-AUTH-001). */
    private final String errorCode;

    protected DomainException(String errorCode, String message) {
        super(message);
        this.errorCode = errorCode;
    }

    public String errorCode() {
        return errorCode;
    }
}
