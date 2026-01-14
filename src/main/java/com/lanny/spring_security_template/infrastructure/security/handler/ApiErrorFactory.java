package com.lanny.spring_security_template.infrastructure.security.handler;

import static com.lanny.spring_security_template.infrastructure.observability.MdcKeys.*;

import java.time.Instant;

import org.slf4j.MDC;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.time.ClockProvider;

import jakarta.servlet.http.HttpServletRequest;

/**
 * ============================================================
 * ApiErrorFactory
 * ============================================================
 *
 * <p>
 * Centralized factory responsible for building {@link ApiError}
 * instances in a safe, consistent and deterministic way.
 * </p>
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
 * <li>Correlation ID is propagated when available</li>
 * </ul>
 *
 * <h2>Design constraints</h2>
 * <ul>
 * <li>This factory does <b>not</b> perform logging</li>
 * <li>This factory does <b>not</b> make authorization decisions</li>
 * <li>Messages must always be client-safe and generic</li>
 * </ul>
 *
 * <p>
 * Infrastructure-only component. Intended to be used by
 * security filters and exception handlers.
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
     * <b>IMPORTANT</b>:
     * </p>
     * <ul>
     * <li>Do NOT pass raw exception messages</li>
     * <li>Do NOT include technical or sensitive information</li>
     * <li>Messages must be safe for external API consumers</li>
     * </ul>
     *
     * @param status  HTTP status code
     * @param message client-safe error message
     * @param request current HTTP request (must not be {@code null})
     * @return immutable {@link ApiError}
     */
    public ApiError create(int status, String message, HttpServletRequest request) {
        return new ApiError(
                now(),
                status,
                message,
                resolvePath(request),
                resolveCorrelationId(request));
    }

    // ======================================================
    // Semantic helpers (preferred usage)
    // ======================================================

    public ApiError unauthorized(HttpServletRequest request) {
        return create(401, "Unauthorized", request);
    }

    public ApiError forbidden(HttpServletRequest request) {
        return create(403, "Forbidden", request);
    }

    public ApiError tooManyRequests(HttpServletRequest request) {
        return create(429, "Too many requests", request);
    }

    // ======================================================
    // Internals
    // ======================================================

    private String resolveCorrelationId(HttpServletRequest request) {

        String headerValue = request.getHeader(CORRELATION_HEADER);
        if (headerValue != null && !headerValue.isBlank()) {
            return headerValue;
        }

        String mdcValue = MDC.get(CORRELATION_ID);
        if (mdcValue != null && !mdcValue.isBlank()) {
            return mdcValue;
        }

        return null; // Allowed: consumers must tolerate missing correlationId
    }

    private String resolvePath(HttpServletRequest request) {
        try {
            return request.getRequestURI();
        } catch (Exception ex) {
            return "unknown";
        }
    }

    private Instant now() {
        return clockProvider.now();
    }
}
