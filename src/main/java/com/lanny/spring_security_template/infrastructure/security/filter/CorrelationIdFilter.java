package com.lanny.spring_security_template.infrastructure.security.filter;

import static com.lanny.spring_security_template.infrastructure.observability.MdcKeys.*;

import java.io.IOException;
import java.util.UUID;

import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.lanny.spring_security_template.infrastructure.security.network.ClientIpResolver;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * {@code CorrelationIdFilter}
 *
 * <p>
 * Establishes a request-scoped correlation context for:
 * </p>
 * <ul>
 * <li>Structured logging</li>
 * <li>Security auditing</li>
 * <li>Metrics and tracing</li>
 * </ul>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Propagate or generate a correlation ID</li>
 * <li>Expose the correlation ID in the response</li>
 * <li>Populate MDC with request metadata</li>
 * <li>Ensure safe MDC cleanup</li>
 * </ul>
 *
 * <h2>Important design decision</h2>
 * <p>
 * This filter does <b>NOT</b> resolve the client IP directly.
 * IP resolution is delegated to {@link ClientIpResolver} to avoid
 * security issues related to spoofed forwarded headers.
 * </p>
 * 
 * 
 * <p>
 * NOTE:
 * This filter is compatible with distributed tracing systems
 * (e.g. OpenTelemetry, Sleuth) and intentionally does not override
 * existing trace/span identifiers if present.
 * </p>
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";

    private final ClientIpResolver ipResolver;

    public CorrelationIdFilter(ClientIpResolver ipResolver) {
        this.ipResolver = ipResolver;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain) throws ServletException, IOException {

        String correlationId = resolveCorrelationId(request);

        try {
            // Propagate correlation ID
            response.setHeader(CORRELATION_HEADER, correlationId);

            // Populate MDC
            MDC.put(CORRELATION_ID, correlationId);
            MDC.put(REQUEST_PATH, request.getMethod() + " " + request.getRequestURI());
            MDC.put(CLIENT_IP, ipResolver.resolve(request));

            chain.doFilter(request, response);

        } finally {
            // Remove ONLY keys introduced by this filter
            MDC.remove(CORRELATION_ID);
            MDC.remove(REQUEST_PATH);
            MDC.remove(CLIENT_IP);
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
}
