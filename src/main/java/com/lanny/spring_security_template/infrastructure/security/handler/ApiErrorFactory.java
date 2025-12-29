package com.lanny.spring_security_template.infrastructure.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.time.ClockProvider;

import java.time.Instant;

/**
 * ApiErrorFactory
 *
 * Centralized factory for building {@link ApiError} responses.
 *
 * <p>
 * Responsibilities:
 * <ul>
 * <li>Generate deterministic timestamps using {@link ClockProvider}</li>
 * <li>Standardize error messages and HTTP status mapping</li>
 * <li>Extract request metadata (path, correlation-id)</li>
 * </ul>
 *
 * <p>
 * This design ensures:
 * <ul>
 * <li>Consistent error responses across the application</li>
 * <li>Full testability (fixed clocks in tests)</li>
 * <li>No duplication of error construction logic in handlers or filters</li>
 * </ul>
 */
@Component
public class ApiErrorFactory {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";

    private final ClockProvider clockProvider;

    public ApiErrorFactory(ClockProvider clockProvider) {
        this.clockProvider = clockProvider;
    }

    // ======================================================
    // Generic factory
    // ======================================================

    /**
     * Builds a generic {@link ApiError}.
     *
     * @param status  HTTP status code
     * @param message error message
     * @param request current HTTP request
     * @return immutable ApiError instance
     */
    public ApiError create(int status, String message, HttpServletRequest request) {
        return new ApiError(
                now(),
                status,
                message,
                request.getRequestURI(),
                request.getHeader(CORRELATION_HEADER));
    }

    // ======================================================
    // Semantic helpers (preferred)
    // ======================================================

    /**
     * Builds a standard 401 Unauthorized error.
     */
    public ApiError unauthorized(HttpServletRequest request) {
        return create(401, "Unauthorized", request);
    }

    /**
     * Builds a standard 403 Forbidden error.
     */
    public ApiError forbidden(HttpServletRequest request) {
        return create(403, "Forbidden", request);
    }

    /**
     * Builds a standard 429 Too Many Requests error.
     */
    public ApiError tooManyRequests(HttpServletRequest request) {
        return create(429, "Too many requests", request);
    }

    // ======================================================
    // Internals
    // ======================================================

    private Instant now() {
        return clockProvider.now();
    }
}
