package com.lanny.spring_security_template.domain.exception;

/**
 * Thrown when a refresh token reuse (double-spend) is detected.
 *
 * <p>
 * This exception represents a security-critical condition where
 * the same refresh token identifier (JTI) is used more than once.
 * </p>
 *
 * <p>
 * Typical causes:
 * </p>
 * <ul>
 * <li>Refresh token replay attack</li>
 * <li>Concurrent refresh attempts</li>
 * <li>Client-side bug or malicious behavior</li>
 * </ul>
 *
 * <p>
 * This exception must trigger:
 * </p>
 * <ul>
 * <li>Immediate request rejection</li>
 * <li>Security audit event</li>
 * <li>Optional session invalidation</li>
 * </ul>
 */
public final class RefreshTokenReuseDetectedException extends DomainException {

    private static final String CODE = "ERR-AUTH-025";
    private static final String KEY = "auth.refresh_token_reuse_detected";
    private static final String DEFAULT_MESSAGE = "Refresh token reuse detected";

    /** Default constructor with standard message. */
    public RefreshTokenReuseDetectedException() {
        super(CODE, KEY, DEFAULT_MESSAGE);
    }

    /** Allows overriding the default message when needed. */
    public RefreshTokenReuseDetectedException(String message) {
        super(CODE, KEY, message);
    }
}
