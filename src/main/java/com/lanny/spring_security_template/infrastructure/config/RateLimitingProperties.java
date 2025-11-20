package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Strongly-typed configuration for login rate limiting.
 * Bound from the "rate-limiting" prefix in application-*.yml.
 */
@ConfigurationProperties(prefix = "rate-limiting")
public record RateLimitingProperties(
        boolean enabled,
        String strategy,
        int maxAttempts,
        long window,
        long blockSeconds,
        long retryAfter,
        String loginPath
) {
}

