package com.lanny.spring_security_template.infrastructure.security.jwt;

import com.lanny.spring_security_template.infrastructure.security.jwt.exception.InvalidTokenTypeException;

/**
 * ============================================================
 * TokenUse
 * ============================================================
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
 * <h2>Security contract</h2>
 * <ul>
 * <li>Parsing is case-insensitive</li>
 * <li>Never returns {@code null}</li>
 * <li>No fallback or default behavior</li>
 * <li>Any invalid value results in a security exception</li>
 * </ul>
 */
public enum TokenUse {

    ACCESS,
    REFRESH;

    /**
     * Parses and validates the {@code token_use} claim.
     *
     * @param raw raw claim value (may be null or blank)
     * @return validated {@link TokenUse}
     * @throws InvalidTokenTypeException if the value is missing or invalid
     */
    public static TokenUse from(String raw) {

        if (raw == null || raw.isBlank()) {
            throw new InvalidTokenTypeException();
        }

        try {
            return TokenUse.valueOf(raw.trim().toUpperCase());
        } catch (IllegalArgumentException ex) {
            throw new InvalidTokenTypeException();
        }
    }
}
