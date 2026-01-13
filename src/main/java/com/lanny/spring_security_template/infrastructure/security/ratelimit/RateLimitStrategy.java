package com.lanny.spring_security_template.infrastructure.security.ratelimit;

/**
 * Supported rate limiting strategies.
 *
 * <p>
 * Only production-safe strategies are allowed.
 * </p>
 */
public enum RateLimitStrategy {

    /**
     * Rate limit by resolved client IP.
     */
    IP,

    /**
     * Rate limit by resolved client IP + hashed username.
     */
    IP_USER
}
