package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import com.lanny.spring_security_template.application.auth.result.JwtResult;

/**
 * Immutable value object representing an issued authentication token pair
 * (access + refresh) along with its associated metadata.
 *
 * <p>
 * This record acts as the canonical representation of a JWT lifecycle event
 * inside the authentication subsystem. It encapsulates:
 * </p>
 *
 * <ul>
 * <li>The authenticated <strong>username</strong></li>
 * <li>The issued <strong>access token</strong> and its expiration time</li>
 * <li>The issued <strong>refresh token</strong>, its JTI and its expiration
 * time</li>
 * <li>The complete set of <strong>roles</strong> and <strong>scopes</strong>
 * assigned at issuance</li>
 * <li>A monotonic <strong>issuedAt</strong> timestamp used for auditing,
 * traceability and token rotation policies</li>
 * </ul>
 *
 * <h2>Responsibility</h2>
 * <p>
 * {@code IssuedTokens} provides a stable, domain-friendly abstraction over
 * low-level JWT operations performed by the token encoder. It is used by:
 * </p>
 *
 * <ul>
 * <li>{@code LoginService} during initial authentication</li>
 * <li>{@code RefreshService} during token renewal</li>
 * <li>{@code AuthUseCaseLoggingDecorator} for audit logging</li>
 * <li>Controllers and adapters to produce REST-facing {@link JwtResult}</li>
 * </ul>
 *
 * <h2>Validation</h2>
 * <p>
 * The compact constructor enforces strict chronological consistency:
 * </p>
 * 
 * <pre>
 * issuedAt &lt;= accessExp &lt;= refreshExp
 * </pre>
 *
 * If the order is violated, an {@link IllegalArgumentException} is raised.
 *
 * <h2>Immutability & Thread Safety</h2>
 * <p>
 * As a Java {@code record}, this type is fully immutable, inherently
 * thread-safe, and safe to store in caches or exchange across layers.
 * </p>
 *
 * <h2>Usage</h2>
 * <p>
 * The record exposes helper methods to convert into a REST-layer response or
 * a formatted audit string. It deliberately contains no security logic; that
 * responsibility is delegated to token encoders and use-case services.
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

    /**
     * Compact constructor with invariants enforcing non-null fields and valid
     * token expiration chronology.
     *
     * @throws IllegalArgumentException if any timestamp is null or the ordering
     *                                  {@code issuedAt → accessExp → refreshExp}
     *                                  is violated.
     */
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

    /**
     * Converts this internal representation into a REST-layer DTO used by
     * controllers.
     *
     * @return a {@link JwtResult} carrying access token, refresh token, and access
     *         expiry
     */
    public JwtResult toJwtResult() {
        return new JwtResult(accessToken, refreshToken, accessExp);
    }

    /**
     * Produces a structured string suitable for audit logs, security tracing,
     * or metrics correlation.
     *
     * @return formatted string containing user, roles, scopes and expiration dates
     */
    public String toAuditDetails() {
        return String.format(
                "User=%s, Roles=%s, Scopes=%s, Issued=%s, Expires=%s",
                username, roleNames, scopeNames, issuedAt, refreshExp);
    }
}
