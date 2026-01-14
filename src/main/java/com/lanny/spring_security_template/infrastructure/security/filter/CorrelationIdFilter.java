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
 * ============================================================
 * CorrelationIdFilter
 * ============================================================
 *
 * <p>
 * Establishes a request-scoped correlation context used for
 * logging, security auditing, metrics and distributed tracing.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Propagate or generate a correlation ID</li>
 * <li>Expose the correlation ID in the response</li>
 * <li>Populate MDC with request metadata</li>
 * <li>Ensure deterministic MDC cleanup</li>
 * </ul>
 *
 * <h2>Design guarantees</h2>
 * <ul>
 * <li>Never throws exceptions</li>
 * <li>Never alters response status or body</li>
 * <li>Never clears MDC keys it did not introduce</li>
 * <li>Safe for async and error dispatches</li>
 * </ul>
 *
 * <p>
 * This filter runs at the highest precedence to ensure
 * correlation data is available to all downstream components.
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
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        // Skip async and error dispatches
        return isAsyncDispatch(request) || request.getDispatcherType().name().equals("ERROR");
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain)
            throws ServletException, IOException {

        String correlationId = resolveCorrelationId(request);

        try {
            // This service is the authority for the correlation ID
            response.setHeader(CORRELATION_HEADER, correlationId);

            MDC.put(CORRELATION_ID, correlationId);
            MDC.put(REQUEST_PATH, request.getMethod() + " " + request.getRequestURI());
            MDC.put(CLIENT_IP, ipResolver.resolve(request));

            chain.doFilter(request, response);

        } finally {
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
