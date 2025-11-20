package com.lanny.spring_security_template.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.lang.NonNull;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;

@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)  
public class CorrelationIdFilter extends OncePerRequestFilter {

    private static final String CORRELATION_HEADER = "X-Correlation-Id";
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        try {
            // 1) Obtener o generar ID
            String correlationId = request.getHeader(CORRELATION_HEADER);
            if (correlationId == null || correlationId.isBlank()) {
                correlationId = UUID.randomUUID().toString();
            }

            // 2) Añadir al response
            response.setHeader(CORRELATION_HEADER, correlationId);

            // 3) Añadir al MDC para logs
            MDC.put("correlationId", correlationId);
            MDC.put("path", request.getRequestURI());
            MDC.put("ip", request.getRemoteAddr());

            log.debug("➡️ Incoming request {} [{}]", request.getRequestURI(), correlationId);

            chain.doFilter(request, response);

        } finally {
            // 4) Limpieza obligatoria (evita fugas en contenedores)
            MDC.clear();
        }
    }
}

