package com.lanny.spring_security_template.infrastructure.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;

/**
 *  ApiError
 *
 * Estructura estándar para respuestas JSON de error.
 * Usado por AuthenticationEntryPoint y AccessDeniedHandler.
 */
public record ApiError(
        Instant timestamp,
        int status,
        String error,
        String path,
        String correlationId
) {
    public static ApiError of(int status, String error, HttpServletRequest req) {
        return new ApiError(
                Instant.now(),
                status,
                error,
                req.getRequestURI(),
                req.getHeader("X-Correlation-Id")
        );
    }
}
