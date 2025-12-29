package com.lanny.spring_security_template.infrastructure.security.handler;

import java.time.Instant;

/**
 * ApiError
 *
 * Immutable error representation for HTTP responses.
 */
public record ApiError(
        Instant timestamp,
        int status,
        String error,
        String path,
        String correlationId) {
}
