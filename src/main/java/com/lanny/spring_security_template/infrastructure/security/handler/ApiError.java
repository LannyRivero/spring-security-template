package com.lanny.spring_security_template.infrastructure.security.handler;

import java.time.Instant;

/**
 * {@code ApiError}
 *
 * Immutable, client-safe error representation for HTTP responses.
 *
 * <p>
 * Design rules:
 * </p>
 * <ul>
 * <li>Error messages are generic and client-facing</li>
 * <li>No technical details or exception messages are exposed</li>
 * <li>CorrelationId enables request tracing across systems</li>
 * </ul>
 *
 * <p>
 * Suitable for security-sensitive, production-grade REST APIs.
 * </p>
 */
public record ApiError(
                Instant timestamp,
                int status,
                String error,
                String path,
                String correlationId) {
}
