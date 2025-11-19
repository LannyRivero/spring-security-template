package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;

public interface RateLimitKeyResolver {
    String resolveKey(HttpServletRequest request);
}

