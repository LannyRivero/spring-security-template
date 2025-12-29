package com.lanny.spring_security_template.infrastructure.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * CustomAccessDeniedHandler — handles 403 errors in JSON format.
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

        log.warn("Access denied: {}", ex.getMessage());

        ApiError error = errorFactory.create(
                HttpServletResponse.SC_FORBIDDEN,
                "Forbidden",
                request);

        response.setStatus(error.status());
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        mapper.writeValue(response.getWriter(), error);
    }
}
