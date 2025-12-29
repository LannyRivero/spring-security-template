package com.lanny.spring_security_template.infrastructure.security.handler;

import com.lanny.spring_security_template.domain.time.ClockProvider;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Factory responsible for creating ApiError instances
 * using a consistent time source.
 */
@Component
public class ApiErrorFactory {

    private final ClockProvider clock;

    public ApiErrorFactory(ClockProvider clock) {
        this.clock = clock;
    }

    public ApiError create(
            int status,
            String error,
            HttpServletRequest request) {
        return new ApiError(
                clock.now(),
                status,
                error,
                request.getRequestURI(),
                request.getHeader("X-Correlation-Id"));
    }
}
