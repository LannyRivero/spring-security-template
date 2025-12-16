package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Strongly-typed configuration for login rate limiting.
 *
 * All values are validated at startup to ensure safe, predictable behavior.
 */
@Validated
@ConfigurationProperties(prefix = "rate-limiting")
public record RateLimitingProperties(

        /** Whether rate limiting is active. */
        boolean enabled,

        /** Strategy used to build the rate-limiting key. */
        @NotBlank(message = "strategy cannot be blank") @Pattern(regexp = "IP|USER|IP_USER", message = "strategy must be one of: IP, USER, IP_USER") String strategy,

        /** Max allowed failed attempts. */
        @Min(value = 1, message = "maxAttempts must be >= 1") int maxAttempts,

        /** Window duration (seconds). */
        @Min(value = 1, message = "window must be >= 1") long window,

        /** Block duration after exceeding attempts (seconds). */
        @Min(value = 1, message = "blockSeconds must be >= 1") long blockSeconds,

        /** Value for Retry-After header (seconds). */
        @Min(value = 1, message = "retryAfter must be >= 1") long retryAfter,

        /** Login endpoint to protect. */
        @NotBlank(message = "loginPath cannot be blank") @Pattern(regexp = "^/.*$", message = "loginPath must start with '/'") String loginPath) {

    public RateLimitingProperties {
        // --- Cross-field validation ---
        if (retryAfter > blockSeconds) {
            throw new IllegalArgumentException(
                    "retryAfter must be <= blockSeconds");
        }
    }
}
