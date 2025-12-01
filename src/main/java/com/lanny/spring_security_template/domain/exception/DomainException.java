package com.lanny.spring_security_template.domain.exception;

import java.io.Serial;

/**
 * Base class for all domain-level exceptions.
 *
 * <p>
 * Domain exceptions represent violations of business rules or
 * authentication/authorization policies. They must never leak to external
 * clients directly; instead, adapters should translate them into uniform
 * ApiError responses.
 * </p>
 */
public abstract class DomainException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /** Machine-readable internal error code (e.g., ERR-AUTH-001). */
    private final String errorCode;

    /** Message key for i18n and client-facing error mapping. */
    private final String messageKey;

    protected DomainException(String errorCode, String messageKey, String message) {
        super(message);
        this.errorCode = errorCode;
        this.messageKey = messageKey;
    }

    public String errorCode() {
        return errorCode;
    }

    public String messageKey() {
        return messageKey;
    }
}
