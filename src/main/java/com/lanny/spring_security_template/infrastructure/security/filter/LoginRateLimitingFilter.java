package com.lanny.spring_security_template.infrastructure.security.filter;

import java.io.IOException;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.security.handler.ApiError;
import com.lanny.spring_security_template.infrastructure.security.handler.ApiErrorFactory;
import com.lanny.spring_security_template.infrastructure.security.ratelimit.RateLimitKeyResolver;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * {@code LoginRateLimitingFilter}
 *
 * <p>
 * Infrastructure-level security filter that enforces rate limiting
 * on authentication attempts.
 * </p>
 *
 * <h2>Execution scope</h2>
 * <ul>
 * <li>Applies ONLY to POST requests</li>
 * <li>Applies ONLY to the configured login endpoint</li>
 * <li>Disabled automatically when rate limiting is off</li>
 * </ul>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Resolve rate-limit key via {@link RateLimitKeyResolver}</li>
 * <li>Delegate brute-force detection to {@link LoginAttemptPolicy}</li>
 * <li>Short-circuit blocked requests with RFC-compliant error responses</li>
 * </ul>
 *
 * <h2>Important note</h2>
 * <p>
 * Resetting login attempts after a successful authentication
 * is the responsibility of the application layer (login use case),
 * NOT this filter.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No PII leakage</li>
 * <li>No logging of rate-limit keys</li>
 * <li>Deterministic behavior</li>
 * </ul>
 */
@Slf4j
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 30)
public class LoginRateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitingProperties props;
    private final RateLimitKeyResolver keyResolver;
    private final ObjectMapper objectMapper;
    private final LoginAttemptPolicy loginAttemptPolicy;
    private final ApiErrorFactory errorFactory;

    public LoginRateLimitingFilter(
            RateLimitingProperties props,
            RateLimitKeyResolver keyResolver,
            ObjectMapper objectMapper,
            LoginAttemptPolicy loginAttemptPolicy,
            ApiErrorFactory errorFactory) {

        this.props = props;
        this.keyResolver = keyResolver;
        this.objectMapper = objectMapper;
        this.loginAttemptPolicy = loginAttemptPolicy;
        this.errorFactory = errorFactory;
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {

        if (!props.enabled()) {
            return true;
        }

        return !props.loginPath().equals(request.getRequestURI())
                || !"POST".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain)
            throws ServletException, IOException {

        String key = keyResolver.resolveKey(request);
        LoginAttemptResult result = loginAttemptPolicy.registerAttempt(key);

        if (!result.allowed()) {

            log.warn(
                    "[RATE_LIMIT] Login blocked [strategy={}, retryAfter={}s]",
                    props.strategy(),
                    result.retryAfterSeconds());

            reject(response, request, result.retryAfterSeconds());
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void reject(
            HttpServletResponse response,
            HttpServletRequest request,
            long retryAfterSeconds) throws IOException {

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setContentType("application/json;charset=UTF-8");

        if (retryAfterSeconds > 0) {
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        }

        ApiError error = errorFactory.create(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "Too many login attempts. Please try again later.",
                request);

        objectMapper.writeValue(response.getWriter(), error);
    }
}
