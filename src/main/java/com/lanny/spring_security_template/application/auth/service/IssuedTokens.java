package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import com.lanny.spring_security_template.application.auth.result.JwtResult;

/**
 * Immutable record representing a pair of issued access and refresh tokens,
 * including metadata for expiration, roles, and scopes.
 *
 * <p>
 * Provides a single source of truth for JWT lifecycle operations
 * such as rotation, revocation, and auditing.
 * </p>
 */
public record IssuedTokens(
        String username,
        String accessToken,
        String refreshToken,
        String refreshJti,
        Instant issuedAt,
        Instant accessExp,
        Instant refreshExp,
        List<String> roleNames,
        List<String> scopeNames) {

    public IssuedTokens {
        Objects.requireNonNull(username, "username must not be null");
        Objects.requireNonNull(accessToken, "accessToken must not be null");
        Objects.requireNonNull(refreshToken, "refreshToken must not be null");
        Objects.requireNonNull(issuedAt, "issuedAt must not be null");
        Objects.requireNonNull(accessExp, "accessExp must not be null");
        Objects.requireNonNull(refreshExp, "refreshExp must not be null");

        if (issuedAt.isAfter(accessExp) || accessExp.isAfter(refreshExp)) {
            throw new IllegalArgumentException("Invalid token expiration chronology");
        }
    }

    /** Converts this record into a transport-layer result for REST responses. */
    public JwtResult toJwtResult() {
        return new JwtResult(accessToken, refreshToken, accessExp);
    }

    /** Returns a formatted audit string for logging and tracing. */
    public String toAuditDetails() {
        return String.format(
                "User=%s, Roles=%s, Scopes=%s, Issued=%s, Expires=%s",
                username, roleNames, scopeNames, issuedAt, refreshExp);
    }
}
