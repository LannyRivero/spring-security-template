package com.lanny.spring_security_template.infrastructure.security.handler;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * ============================================================
 * CustomAuthEntryPoint
 * ============================================================
 *
 * <p>
 * Handles authentication failures (HTTP 401 Unauthorized) in a
 * secure, deterministic and client-safe way.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Translate authentication failures into HTTP 401 responses</li>
 * <li>Delegate error construction to {@link ApiErrorFactory}</li>
 * <li>Serialize a standardized JSON error body</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No internal authentication details are exposed</li>
 * <li>No exception messages are leaked to clients or logs</li>
 * <li>Response format is stable and predictable</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>This component performs no authentication logic</li>
 * <li>Error semantics are centralized in {@link ApiErrorFactory}</li>
 * <li>All authentication failures are intentionally collapsed into 401</li>
 * </ul>
 */
@Component
public class CustomAuthEntryPoint implements AuthenticationEntryPoint {

    private static final Logger log = LoggerFactory.getLogger(CustomAuthEntryPoint.class);

    private final ObjectMapper mapper;
    private final ApiErrorFactory errorFactory;

    public CustomAuthEntryPoint(
            ObjectMapper mapper,
            ApiErrorFactory errorFactory) {
        this.mapper = mapper;
        this.errorFactory = errorFactory;
    }

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException ex) throws IOException {

        // Log minimal, non-sensitive information only
        log.warn("Unauthorized request (401) for path={}", request.getRequestURI());

        ApiError error = errorFactory.unauthorized(request);

        response.resetBuffer(); // defensive: avoid mixed responses
        response.setStatus(error.status());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        mapper.writeValue(response.getWriter(), error);
    }
}
