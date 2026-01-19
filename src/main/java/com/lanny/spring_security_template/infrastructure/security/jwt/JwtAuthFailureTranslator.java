package com.lanny.spring_security_template.infrastructure.security.jwt;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

/**
 * ============================================================
 * JwtAuthFailureTranslator
 * ============================================================
 *
 * Centralized translator that converts normalized JWT authentication
 * and authorization failure reasons into Spring Security exceptions.
 *
 * <p>
 * This component is the <b>single authority</b> responsible for deciding
 * whether a JWT-related failure results in:
 * </p>
 * <ul>
 * <li><b>Authentication failure</b> → HTTP 401</li>
 * <li><b>Authorization failure</b> → HTTP 403</li>
 * </ul>
 *
 * <p>
 * It deliberately does <b>not</b>:
 * </p>
 * <ul>
 * <li>Write HTTP responses</li>
 * <li>Log messages</li>
 * <li>Expose technical exception details</li>
 * </ul>
 *
 * <p>
 * Those concerns are handled by:
 * </p>
 * <ul>
 * <li>Spring Security exception handling</li>
 * <li>AuthenticationEntryPoint / AccessDeniedHandler</li>
 * <li>{@code ApiErrorFactory}</li>
 * </ul>
 *
 * <h2>Design principles</h2>
 * <ul>
 * <li><b>Single responsibility</b>: failure classification only</li>
 * <li><b>Deterministic mapping</b>: same reason → same outcome</li>
 * <li><b>Fail-safe defaults</b>: unknown reasons never result in HTTP 500</li>
 * <li><b>Infrastructure-only</b>: no coupling with application or domain
 * layers</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>JWT failures never propagate as unhandled runtime exceptions</li>
 * <li>Malformed or invalid tokens always map to HTTP 401</li>
 * <li>Authorization violations always map to HTTP 403</li>
 * <li>No sensitive information is leaked through exception messages</li>
 * </ul>
 *
 * <p>
 * This translator is typically invoked by infrastructure-level security
 * filters (e.g. {@code JwtAuthorizationFilter}) and must remain stable
 * over time to preserve observability and client contracts.
 * </p>
 */
@Component
public final class JwtAuthFailureTranslator {

    /**
     * Translates a normalized {@link JwtAuthFailureReason} into a
     * Spring Security runtime exception.
     *
     * <p>
     * The returned exception is intentionally chosen so that Spring Security
     * can map it to the correct HTTP status code:
     * </p>
     * <ul>
     * <li>{@link BadCredentialsException} →
     * handled by {@code AuthenticationEntryPoint} → HTTP 401</li>
     * <li>{@link AccessDeniedException} →
     * handled by {@code AccessDeniedHandler} → HTTP 403</li>
     * </ul>
     *
     * <p>
     * This method must never return {@code null} and must never throw
     * unchecked exceptions other than the returned one.
     * </p>
     *
     * @param reason normalized JWT authentication/authorization failure reason
     * @param ex     original exception that triggered the failure
     *               (used only as cause, never exposed to clients)
     * @return a Spring Security exception that enforces the correct HTTP semantics
     */
    public RuntimeException translate(
            JwtAuthFailureReason reason,
            Exception ex) {

        // ---------- AUTHENTICATION (401) ----------
        if (isAuthenticationFailure(reason)) {
            return new BadCredentialsException("Invalid JWT token", ex);
        }

        // ---------- AUTHORIZATION (403) ----------
        if (isAuthorizationFailure(reason)) {
            return new AccessDeniedException("Insufficient permissions");
        }

        // ---------- FAIL-SAFE FALLBACK ----------
        return new AuthenticationServiceException(
                "Unexpected JWT authentication error", ex);
    }

    /**
     * Determines whether a failure reason represents an authentication failure.
     *
     * <p>
     * Authentication failures indicate that the request could not be
     * authenticated and therefore must result in HTTP 401.
     * </p>
     */
    private boolean isAuthenticationFailure(JwtAuthFailureReason reason) {
        return switch (reason) {
            case MISSING_TOKEN,
                    INVALID_FORMAT,
                    INVALID_SIGNATURE,
                    INVALID_CREDENTIALS,
                    TOKEN_EXPIRED,
                    TOKEN_REVOKED,
                    INVALID_CLAIMS,
                    INVALID_TYPE,
                    UNKNOWN ->
                true;
            default -> false;
        };
    }

    /**
     * Determines whether a failure reason represents an authorization failure.
     *
     * <p>
     * Authorization failures indicate that the user was authenticated but
     * lacks sufficient privileges to access the requested resource and
     * therefore must result in HTTP 403.
     * </p>
     */
    private boolean isAuthorizationFailure(JwtAuthFailureReason reason) {
        return switch (reason) {
            case ACCESS_DENIED,
                    NO_AUTHORITIES ->
                true;
            default -> false;
        };
    }
}
