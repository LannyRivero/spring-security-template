package com.lanny.spring_security_template.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

import static com.lanny.spring_security_template.infrastructure.observability.MdcKeys.*;

/**
 * {@code CorrelationIdFilter}
 *
 * <p>
 * Establishes a request-scoped correlation context used for
 * <b>logging, auditing, metrics and distributed tracing</b>.
 * </p>
 *
 * <p>
 * Responsibilities:
 * </p>
 * <ul>
 *   <li>Propagate an incoming correlation ID when present</li>
 *   <li>Generate a new correlation ID when missing or invalid</li>
 *   <li>Expose the correlation ID in the HTTP response</li>
 *   <li>Populate MDC with request-scoped metadata</li>
 *   <li>Guarantee MDC cleanup to prevent thread-local leakage</li>
 * </ul>
 *
 * <h2>Execution order</h2>
 * <p>
 * This filter is executed with the <b>highest precedence</b> to ensure
 * that correlation data is available to all downstream filters,
 * security components and application logic.
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 *   <li>No business logic is executed in this filter</li>
 *   <li>Correlation ID format is strictly validated</li>
 *   <li>Safe for use behind gateways, load balancers and reverse proxies</li>
 * </ul>
 *
 * <p>
 * Designed for <b>production-grade, enterprise systems</b> requiring
 * reliable end-to-end request traceability.
 * </p>
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";
    private static final String FORWARDED_FOR_HEADER = "X-Forwarded-For";

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        try {
            // Resolve or generate correlation ID
            String correlationId = resolveCorrelationId(request);

            // Propagate to response
            response.setHeader(CORRELATION_HEADER, correlationId);

            // Populate MDC
            MDC.put(CORRELATION_ID, correlationId);
            MDC.put(REQUEST_PATH, request.getRequestURI());
            MDC.put(CLIENT_IP, resolveClientIp(request));

            chain.doFilter(request, response);

        } finally {
            // Mandatory cleanup to avoid thread-local leakage
            MDC.clear();
        }
    }

    private String resolveCorrelationId(HttpServletRequest request) {
        String headerValue = request.getHeader(CORRELATION_HEADER);
        if (isValidUuid(headerValue)) {
            return headerValue;
        }
        return UUID.randomUUID().toString();
    }

    private boolean isValidUuid(String value) {
        if (value == null || value.isBlank()) {
            return false;
        }
        try {
            UUID.fromString(value);
            return true;
        } catch (IllegalArgumentException ex) {
            return false;
        }
    }

    private String resolveClientIp(HttpServletRequest request) {
        String forwardedFor = request.getHeader(FORWARDED_FOR_HEADER);
        if (forwardedFor != null && !forwardedFor.isBlank()) {
            return forwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }
}

