package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

import com.lanny.spring_security_template.infrastructure.security.ratelimit.RateLimitStrategy;

/**
 * Strongly-typed configuration for login rate limiting.
 *
 * <p>
 * All values are validated at startup to ensure safe and predictable behavior.
 * </p>
 */
@Validated
@ConfigurationProperties(prefix = "rate-limiting")
public record RateLimitingProperties(

        /** Whether rate limiting is active. */
        boolean enabled,

        /** Strategy used to build the rate-limiting key. */
        @NotNull(message = "strategy must be specified") RateLimitStrategy strategy,

        /** Max allowed failed attempts. */
        @Min(value = 1, message = "maxAttempts must be >= 1") int maxAttempts,

        /** Window duration (seconds). */
        @Min(value = 1, message = "window must be >= 1") long window,

        /** Block duration after exceeding attempts (seconds). */
        @Min(value = 1, message = "blockSeconds must be >= 1") long blockSeconds,

        /** Value for Retry-After header (seconds). */
        @Min(value = 1, message = "retryAfter must be >= 1") long retryAfter,

        /** Login endpoint to protect. */
        @NotBlank(message = "loginPath cannot be blank") String loginPath) {

    public RateLimitingProperties {
        // --- Cross-field validation ---
        if (retryAfter > blockSeconds) {
            throw new IllegalArgumentException(
                    "retryAfter must be <= blockSeconds");
        }
    }
}
