package com.lanny.spring_security_template.infrastructure.security.jwt.exception;

/**
 * Thrown when a mandatory JWT claim is missing or invalid.
 *
 * <p>
 * Mandatory claims are required for correct authentication and
 * authorization decisions.
 * </p>
 *
 * <p>
 * This exception exposes only the claim name, never the claim value,
 * to avoid leaking sensitive token data.
 * </p>
 */
public class MissingJwtClaimException extends RuntimeException {

    private final String claimName;

    public MissingJwtClaimException(String claimName) {
        super("Missing mandatory JWT claim: " + claimName);
        this.claimName = claimName;
    }

    /**
     * @return the name of the missing claim
     */
    public String getClaimName() {
        return claimName;
    }
}
