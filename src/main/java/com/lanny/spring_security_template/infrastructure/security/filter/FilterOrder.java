package com.lanny.spring_security_template.infrastructure.security.filter;

import org.springframework.core.Ordered;

/**
 * {@code FilterOrder}
 *
 * <p>
 * Centralized registry defining the relative execution order of
 * custom security filters within the Spring Security filter chain.
 * </p>
 *
 * <p>
 * Using a shared ordering contract avoids hardcoded values and
 * guarantees a predictable, auditable filter execution sequence.
 * </p>
 *
 * <h2>Filter execution order</h2>
 * <ol>
 * <li>{@code CorrelationIdFilter} – establishes request traceability</li>
 * <li>{@code SecurityHeadersFilter} – applies HTTP security headers</li>
 * <li>{@code LoginRateLimitingFilter} – protects authentication endpoints</li>
 * <li>{@code JwtAuthorizationFilter} – validates access tokens</li>
 * <li>{@code AuthNoCacheFilter} – disables caching for authenticated
 * responses</li>
 * </ol>
 *
 * <p>
 * Gaps between order values are intentional to allow future filters
 * to be inserted without breaking the existing chain.
 * </p>
 */
public final class FilterOrder {

    private FilterOrder() {
    }

    public static final int CORRELATION_ID = Ordered.HIGHEST_PRECEDENCE;

    public static final int SECURITY_HEADERS = CORRELATION_ID + 10;

    public static final int RATE_LIMITING = SECURITY_HEADERS + 10;

    public static final int JWT_AUTHORIZATION = RATE_LIMITING + 10;

    public static final int AUTH_NO_CACHE = JWT_AUTHORIZATION + 10;
}
