package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

/**
 * Central, strongly-typed configuration for login rate limiting.
 *
 * <p>
 * All fields are mapped from the <code>rate-limiting.*</code> namespace in
 * <code>application.yml</code>.
 * </p>
 *
 * <h2>Business Meaning</h2>
 * <ul>
 * <li><b>enabled</b> — Activates or disables login rate limiting.</li>
 * <li><b>strategy</b> — Key resolution strategy (e.g., IP, USER, IP_USER).</li>
 * <li><b>maxAttempts</b> — Maximum failed attempts allowed before
 * blocking.</li>
 * <li><b>window</b> — Time window (in seconds) for counting attempts.</li>
 * <li><b>blockSeconds</b> — How long the client is blocked after exceeding
 * maxAttempts.</li>
 * <li><b>retryAfter</b> — Suggested "Retry-After" HTTP header for clients.</li>
 * <li><b>loginPath</b> — Path protected by rate limiting (e.g.,
 * /api/v1/auth/login).</li>
 * </ul>
 *
 * <h2>Validation</h2>
 * <p>
 * Input is validated using Jakarta Bean Validation to guarantee:
 * <ul>
 * <li>positive numbers</li>
 * <li>non-blank key fields</li>
 * </ul>
 * This prevents silent misconfiguration at startup.
 * </p>
 */
@Validated
@ConfigurationProperties(prefix = "rate-limiting")
public record RateLimitingProperties(

                /** Whether rate limiting is active. */
                boolean enabled,

                /** Strategy used to generate rate-limit keys (IP, USER, IP_USER). */
                @NotBlank(message = "Rate limiting strategy cannot be blank") String strategy,

                /** Max allowed failed attempts before blocking. */
                @Min(value = 1, message = "maxAttempts must be >= 1") int maxAttempts,

                /** Time window for counting attempts (seconds). */
                @Min(value = 1, message = "window must be >= 1") long window,

                /** How long the user is blocked after exceeding attempts (seconds). */
                @Min(value = 1, message = "blockSeconds must be >= 1") long blockSeconds,

                /** Value used for Retry-After header (seconds). */
                @Min(value = 1, message = "retryAfter must be >= 1") long retryAfter,

                /** Path that rate limiting applies to (usually /api/v1/auth/login). */
                @NotBlank(message = "loginPath cannot be blank") String loginPath) {
}
