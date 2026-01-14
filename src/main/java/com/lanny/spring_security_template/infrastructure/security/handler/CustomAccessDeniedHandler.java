package com.lanny.spring_security_template.infrastructure.security.handler;

import java.io.IOException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * ============================================================
 * CustomAccessDeniedHandler
 * ============================================================
 *
 * <p>
 * Handles authorization failures (HTTP 403 Forbidden) in a
 * secure and consistent manner.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Translate {@link AccessDeniedException} into HTTP 403 responses</li>
 * <li>Delegate error construction to {@link ApiErrorFactory}</li>
 * <li>Serialize client-safe JSON responses</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No internal exception messages are exposed</li>
 * <li>No role, scope or authorization details are leaked</li>
 * <li>Response format is always deterministic</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>This handler performs no authorization logic</li>
 * <li>This handler performs no logging of sensitive data</li>
 * <li>Error semantics are centralized in {@link ApiErrorFactory}</li>
 * </ul>
 */
@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private static final Logger log = LoggerFactory.getLogger(CustomAccessDeniedHandler.class);

    private final ObjectMapper mapper;
    private final ApiErrorFactory errorFactory;

    public CustomAccessDeniedHandler(
            ObjectMapper mapper,
            ApiErrorFactory errorFactory) {
        this.mapper = mapper;
        this.errorFactory = errorFactory;
    }

    @Override
    public void handle(
            HttpServletRequest request,
            HttpServletResponse response,
            AccessDeniedException ex) throws IOException {

        // Log minimal, non-sensitive information only
        log.warn("Access denied (403) for path={}", request.getRequestURI());

        ApiError error = errorFactory.forbidden(request);

        response.resetBuffer(); // defensive: avoid mixed responses
        response.setStatus(error.status());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);

        mapper.writeValue(response.getWriter(), error);
    }
}
