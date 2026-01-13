package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;

/**
 * ============================================================
 * RateLimitKeyResolver
 * ============================================================
 *
 * <p>
 * Strategy interface responsible for deriving deterministic rate-limiting
 * keys from an incoming {@link HttpServletRequest}.
 * </p>
 *
 * <h2>Contract</h2>
 * <ul>
 * <li>Implementations MUST be deterministic</li>
 * <li>Implementations MUST NOT return {@code null}</li>
 * <li>Implementations MUST NOT throw exceptions</li>
 * <li>Implementations MUST be side-effect free</li>
 * </ul>
 *
 * <h2>Security constraints</h2>
 * <ul>
 * <li>No sensitive or personally identifiable information (PII)
 * must be included in clear text</li>
 * <li>Keys should be stable across identical requests</li>
 * </ul>
 *
 * <h2>Execution context</h2>
 * <p>
 * This resolver is invoked early in the request lifecycle, before
 * authentication is established. Implementations must therefore
 * operate safely with partial or missing request data.
 * </p>
 */
public interface RateLimitKeyResolver {

    /**
     * Resolves a rate-limiting key for the given request.
     *
     * @param request incoming HTTP request (never {@code null})
     * @return a non-null, deterministic rate-limiting key
     */
    String resolveKey(HttpServletRequest request);
}
