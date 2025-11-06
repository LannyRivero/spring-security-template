package com.lanny.spring_security_template.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import org.springframework.lang.NonNull;

import java.io.IOException;
import java.util.UUID;

/**
 * 🧩 CorrelationIdFilter
 *
 * Adds or propagates a correlation ID across incoming HTTP requests.
 * This enables request tracing across logs and distributed systems.
 *
 * Future: integrate with observability stack (OpenTelemetry / Sleuth / Zipkin)
 */
@Slf4j
@Order(FilterOrder.CORRELATION_ID)
@Component
public class CorrelationIdFilter extends OncePerRequestFilter {

    public static final String CORRELATION_ID_HEADER = "X-Correlation-Id";
    public static final String MDC_KEY = "correlationId";

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String correlationId = request.getHeader(CORRELATION_ID_HEADER);
        if (correlationId == null || correlationId.isBlank()) {
            correlationId = UUID.randomUUID().toString();
        }

        try {
            // Store in MDC so it's visible in all logs for this thread
            MDC.put(MDC_KEY, correlationId);

            // Add to response headers
            response.setHeader(CORRELATION_ID_HEADER, correlationId);

            // Proceed with the rest of the filter chain
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(MDC_KEY); // cleanup to avoid thread pollution
        }
    }
}
