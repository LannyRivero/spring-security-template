package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * ============================================================
 * InvalidTokenTypeException
 * ============================================================
 *
 * <p>
 * Thrown when a JWT token is used outside of its allowed
 * security context.
 * </p>
 *
 * <h2>Typical scenarios</h2>
 * <ul>
 * <li>Using a refresh token where an access token is required</li>
 * <li>Using an unsupported or unknown token type</li>
 * <li>Violating {@code token_use} claim semantics</li>
 * </ul>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>Does not expose token contents or expected type</li>
 * <li>Used as a control-flow exception in authorization logic</li>
 * </ul>
 *
 * <h2>Performance considerations</h2>
 * <p>
 * Stack trace generation is intentionally disabled to minimize
 * overhead in high-throughput security filters.
 * </p>
 */
public final class InvalidTokenTypeException extends RuntimeException {

    public InvalidTokenTypeException() {
        super("Invalid token type");
    }

    /**
     * Disables stack trace generation for performance reasons.
     */
    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
