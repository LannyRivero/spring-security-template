package com.lanny.spring_security_template.application.auth.exception;

/**
 * ============================================================
 * RefreshTokenReusedException
 * ============================================================
 *
 * Exception thrown when a refresh token replay (reuse) is detected.
 *
 * <p>
 * This exception represents a <strong>security breach signal</strong>,
 * not a functional or validation error.
 * </p>
 *
 * <h2>When is this exception thrown?</h2>
 * <ul>
 * <li>A refresh token is used more than once</li>
 * <li>Concurrent refresh attempts are detected</li>
 * <li>A previously rotated or revoked refresh token is reused</li>
 * </ul>
 *
 * <h2>Security implications</h2>
 * <p>
 * A refresh token replay indicates that:
 * </p>
 * <ul>
 * <li>The token may have been stolen</li>
 * <li>An attacker may be attempting session hijacking</li>
 * </ul>
 *
 * <p>
 * As a mitigation measure, the application layer is expected to:
 * </p>
 * <ul>
 * <li>Revoke the entire refresh token family</li>
 * <li>Invalidate all active sessions associated with the family</li>
 * <li>Emit a high-severity audit event</li>
 * </ul>
 *
 * <h2>Layering rules</h2>
 * <ul>
 * <li>This exception belongs to the <strong>application layer</strong></li>
 * <li>No HTTP, logging, or framework concerns</li>
 * <li>Mapped to responses and audit events in infrastructure</li>
 * </ul>
 */
public class RefreshTokenReusedException extends RuntimeException {

    /**
     * Creates a new RefreshTokenReusedException with a default message.
     */
    public RefreshTokenReusedException() {
        super("Refresh token reuse detected");
    }

    /**
     * Creates a new RefreshTokenReusedException with a custom message.
     *
     * @param message contextual message (must not contain PII)
     */
    public RefreshTokenReusedException(String message) {
        super(message);
    }

    /**
     * Creates a new RefreshTokenReusedException with a root cause.
     *
     * @param message contextual message (must not contain PII)
     * @param cause   underlying cause
     */
    public RefreshTokenReusedException(String message, Throwable cause) {
        super(message, cause);
    }
}
