package com.lanny.spring_security_template.infrastructure.security.handler;

import static com.lanny.spring_security_template.infrastructure.observability.MdcKeys.*;

import java.time.Instant;

import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.time.ClockProvider;

import jakarta.servlet.http.HttpServletRequest;

/**
 * {@code ApiErrorFactory}
 *
 * Centralized factory for building {@link ApiError} responses.
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Generate deterministic timestamps using {@link ClockProvider}</li>
 * <li>Standardize error responses across filters and handlers</li>
 * <li>Safely extract request metadata (path, correlation-id)</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No internal exception messages are exposed</li>
 * <li>No stack traces or technical details leak to clients</li>
 * <li>Correlation ID is always propagated when available</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>This factory does <b>not</b> perform logging</li>
 * <li>This factory does <b>not</b> make authorization decisions</li>
 * <li>Messages must always be client-safe and generic</li>
 * </ul>
 *
 * <p>
 * This component is infrastructure-only and must remain framework-agnostic
 * beyond servlet request access.
 * </p>
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
     * <p>
     * IMPORTANT:
     * <ul>
     * <li>Do NOT pass raw exception messages here</li>
     * <li>Messages must be safe for external clients</li>
     * </ul>
     * </p>
     *
     * @param status  HTTP status code
     * @param message client-safe error message
     * @param request current HTTP request
     * @return immutable {@link ApiError}
     */
    public ApiError create(int status, String message, HttpServletRequest request) {
        return new ApiError(
                now(),
                status,
                message,
                request.getRequestURI(),
                resolveCorrelationId(request));
    }

    // ======================================================
    // Semantic helpers (preferred usage)
    // ======================================================

    /**
     * Builds a standard {@code 401 Unauthorized} error.
     */
    public ApiError unauthorized(HttpServletRequest request) {
        return create(401, "Unauthorized", request);
    }

    /**
     * Builds a standard {@code 403 Forbidden} error.
     */
    public ApiError forbidden(HttpServletRequest request) {
        return create(403, "Forbidden", request);
    }

    /**
     * Builds a standard {@code 429 Too Many Requests} error.
     */
    public ApiError tooManyRequests(HttpServletRequest request) {
        return create(429, "Too many requests", request);
    }

    // ======================================================
    // Internals
    // ======================================================

    /**
     * Resolves the correlation ID in a defensive way.
     *
     * <p>
     * Resolution order:
     * <ol>
     * <li>Request header ({@code X-Correlation-Id})</li>
     * <li>MDC fallback (if filter already populated it)</li>
     * <li>{@code null} (allowed, but discouraged)</li>
     * </ol>
     * </p>
     */
    private String resolveCorrelationId(HttpServletRequest request) {

        String headerValue = request.getHeader(CORRELATION_HEADER);
        if (headerValue != null && !headerValue.isBlank()) {
            return headerValue;
        }

        String mdcValue = MDC.get(CORRELATION_ID);
        if (mdcValue != null && !mdcValue.isBlank()) {
            return mdcValue;
        }

        return null;
    }

    private Instant now() {
        return clockProvider.now();
    }
}
