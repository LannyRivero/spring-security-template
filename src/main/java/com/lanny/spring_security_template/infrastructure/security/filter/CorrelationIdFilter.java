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
 * CorrelationIdFilter
 *
 * <p>
 * Establishes a request-scoped correlation context for logging,
 * auditing and observability.
 * </p>
 *
 * <p>
 * Responsibilities:
 * </p>
 * <ul>
 * <li>Generate or propagate a correlation ID</li>
 * <li>Expose correlation ID in response headers</li>
 * <li>Populate MDC with request metadata</li>
 * <li>Guarantee MDC cleanup</li>
 * </ul>
 *
 * <p>
 * This filter MUST be executed before any security or audit logic.
 * </p>
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class CorrelationIdFilter extends OncePerRequestFilter {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain) throws ServletException, IOException {

        try {
            // Resolve or generate correlation ID
            String correlationId = request.getHeader(CORRELATION_HEADER);
            if (correlationId == null || correlationId.isBlank()) {
                correlationId = UUID.randomUUID().toString();
            }

            // Propagate to response
            response.setHeader(CORRELATION_HEADER, correlationId);

            // Populate MDC (contract-based keys)
            MDC.put(CORRELATION_ID, correlationId);
            MDC.put(REQUEST_PATH, request.getRequestURI());
            MDC.put(CLIENT_IP, request.getRemoteAddr());

            log.debug(
                    "Incoming request path={} correlationId={}",
                    request.getRequestURI(),
                    correlationId);

            chain.doFilter(request, response);

        } finally {
            // Mandatory cleanup to avoid thread-local leakage
            MDC.clear();
        }
    }
}
