package com.lanny.spring_security_template.infrastructure.security.jwt;

import com.lanny.spring_security_template.infrastructure.security.jwt.exception.InvalidJwtAudienceException;

/**
 * TokenUse
 *
 * <p>
 * Enumerates the allowed usages of a JWT within the security domain.
 * </p>
 *
 * <p>
 * This enum is used to strictly validate the {@code token_use} claim
 * and prevent misuse of tokens across security boundaries
 * (e.g. using refresh tokens as access tokens).
 * </p>
 *
 * <h2>Supported values</h2>
 * <ul>
 * <li>{@link #ACCESS} – Access tokens for API authorization</li>
 * <li>{@link #REFRESH} – Refresh tokens for token rotation</li>
 * </ul>
 *
 * <p>
 * Any other value is considered invalid and will result in a
 * security exception.
 * </p>
 */
public enum TokenUse {

    ACCESS,
    REFRESH;

    /**
     * Parses and validates the {@code token_use} claim.
     *
     * @param raw raw claim value
     * @return parsed {@link TokenUse}
     * @throws InvalidJwtAudienceException if the value is invalid
     */
    public static TokenUse from(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new InvalidJwtAudienceException();
        }
        try {
            return TokenUse.valueOf(raw.toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new InvalidJwtAudienceException();
        }
    }
}
