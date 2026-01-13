package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * ============================================================
 * MissingJwtClaimException
 * ============================================================
 *
 * <p>
 * Thrown when a mandatory JWT claim required for authentication
 * or authorization is missing or invalid.
 * </p>
 *
 * <h2>Typical scenarios</h2>
 * <ul>
 * <li>Missing {@code sub}, {@code jti}, {@code aud}, or {@code token_use}</li>
 * <li>Malformed claim type (e.g. non-string where string is expected)</li>
 * </ul>
 *
 * <h2>Security notes</h2>
 * <ul>
 * <li>Exposes only the claim name, never the claim value</li>
 * <li>Used as a control-flow exception during JWT validation</li>
 * </ul>
 *
 * <h2>Performance considerations</h2>
 * <p>
 * Stack trace generation is intentionally disabled as this exception
 * may occur frequently in authorization filters.
 * </p>
 */
public final class MissingJwtClaimException extends RuntimeException {

    private final String claimName;

    public MissingJwtClaimException(String claimName) {
        super("Missing mandatory JWT claim");
        this.claimName = claimName;
    }

    /**
     * @return the name of the missing or invalid claim
     */
    public String getClaimName() {
        return claimName;
    }

    /**
     * Disables stack trace generation for performance reasons.
     */
    @Override
    public synchronized Throwable fillInStackTrace() {
        return this;
    }
}
