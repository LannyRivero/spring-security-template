package com.lanny.spring_security_template.infrastructure.security.filter;

import org.springframework.core.Ordered;

/**
 * Centralized filter order registry.
 * Defines relative filter positions within the Spring Security chain.
 */
public final class FilterOrder {

    private FilterOrder() {}

    public static final int CORRELATION_ID = Ordered.HIGHEST_PRECEDENCE;
    public static final int RATE_LIMITING = CORRELATION_ID + 10;
    public static final int SECURITY_HEADERS = RATE_LIMITING + 10;
    public static final int AUTH_NO_CACHE = SECURITY_HEADERS + 10;
    public static final int JWT_AUTHORIZATION = AUTH_NO_CACHE + 10;
}

