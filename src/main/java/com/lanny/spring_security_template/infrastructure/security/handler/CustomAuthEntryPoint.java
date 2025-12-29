package com.lanny.spring_security_template.infrastructure.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * CustomAuthEntryPoint
 *
 * Handles authentication failures (HTTP 401) and returns
 * a standardized JSON error response.
 *
 * <p>
 * Responsibilities:
 * <ul>
 * <li>Translate authentication errors into HTTP 401 responses</li>
 * <li>Delegate error construction to {@link ApiErrorFactory}</li>
 * <li>Serialize the error using Spring-managed {@link ObjectMapper}</li>
 * </ul>
 *
 * <p>
 * This class contains no business logic and no time-related logic.
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

        log.warn("Unauthorized access: {}", ex.getMessage());

        ApiError error = errorFactory.unauthorized(request);

        response.setStatus(error.status());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        mapper.writeValue(response.getWriter(), error);
    }
}
