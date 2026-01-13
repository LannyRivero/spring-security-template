package com.lanny.spring_security_template.infrastructure.security.jwt;

/**
 * ============================================================
 * JwtAuthFailureReason
 * ============================================================
 *
 * <p>
 * Enumerates normalized reasons for authentication or authorization
 * failure during JWT-based security processing.
 * </p>
 *
 * <h2>Purpose</h2>
 * <ul>
 * <li>Provide a stable classification of security failures</li>
 * <li>Decouple low-level exceptions from HTTP responses</li>
 * <li>Enable consistent logging, metrics and auditing</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <ul>
 * <li>Used internally by security filters and handlers</li>
 * <li>Mapped to HTTP status codes and error responses</li>
 * <li>Never exposed directly to clients as-is</li>
 * </ul>
 *
 * <h2>Design constraints</h2>
 * <ul>
 * <li>Values must be stable over time</li>
 * <li>No environment-specific semantics</li>
 * <li>No sensitive details must be inferred from a single value</li>
 * </ul>
 */
public enum JwtAuthFailureReason {

    /** Authorization header or token is missing */
    MISSING_TOKEN,

    /** Token format is invalid or cannot be parsed */
    INVALID_FORMAT,

    /** Token signature verification failed */
    INVALID_SIGNATURE,

    /** Credentials are invalid or rejected by authentication policy */
    INVALID_CREDENTIALS,

    /** Token is expired based on exp / nbf claims */
    TOKEN_EXPIRED,

    /** Token has been explicitly revoked or invalidated */
    TOKEN_REVOKED,

    /** Mandatory or semantic claims are invalid or missing */
    INVALID_CLAIMS,

    /** Token use or type is not allowed in this context */
    INVALID_TYPE,

    /** Authenticated but not authorized for the requested resource */
    ACCESS_DENIED,

    /** No effective authorities or scopes could be resolved */
    NO_AUTHORITIES,

    /** Fallback for unexpected or uncategorized failures */
    UNKNOWN
}
