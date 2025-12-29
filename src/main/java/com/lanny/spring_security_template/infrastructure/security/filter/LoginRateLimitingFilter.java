package com.lanny.spring_security_template.infrastructure.security.filter;

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

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * {@code LoginRateLimitingFilter}
 *
 * <p>
 * Infrastructure-level security filter that enforces rate limiting
 * on authentication attempts (login endpoint).
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Protect the login endpoint against brute-force attacks</li>
 * <li>Delegate key generation to {@link RateLimitKeyResolver}</li>
 * <li>Delegate attempt tracking and blocking decisions to
 * {@link LoginAttemptPolicy}</li>
 * <li>Return standardized JSON error responses when the limit is exceeded</li>
 * </ul>
 *
 * <h2>Security & Privacy Guarantees</h2>
 * <ul>
 * <li>No personally identifiable information (PII) is logged</li>
 * <li>Rate-limit keys are never exposed in logs or responses</li>
 * <li>Error timestamps are generated via {@link ApiErrorFactory}
 * using {@code ClockProvider}</li>
 * </ul>
 *
 * <h2>Execution Scope</h2>
 * <ul>
 * <li>Applies <strong>only</strong> to the configured login path</li>
 * <li>Applies <strong>only</strong> to HTTP {@code POST} requests</li>
 * <li>Disabled automatically when rate limiting is turned off by
 * configuration</li>
 * </ul>
 *
 * <h2>HTTP Semantics</h2>
 * <ul>
 * <li>Returns {@code 429 Too Many Requests} when blocked</li>
 * <li>Optionally sets {@code Retry-After} header</li>
 * <li>Response body follows the {@link ApiError} structure</li>
 * </ul>
 *
 * <h2>Architectural Notes</h2>
 * <ul>
 * <li>This filter contains <strong>no business logic</strong></li>
 * <li>All policies are delegated to the Application layer</li>
 * <li>Fully compliant with Clean / Hexagonal Architecture</li>
 * <li>Deterministic and fully testable</li>
 * </ul>
 */
@Slf4j
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

    /**
     * Determines whether the current request should be filtered.
     *
     * <p>
     * The filter is applied only when:
     * </p>
     * <ul>
     * <li>Rate limiting is enabled</li>
     * <li>The request URI matches the configured login path</li>
     * <li>The HTTP method is {@code POST}</li>
     * </ul>
     */
    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        if (!props.enabled()) {
            return true;
        }

        return !props.loginPath().equals(request.getRequestURI())
                || !"POST".equalsIgnoreCase(request.getMethod());
    }

    /**
     * Executes the rate limiting check before allowing the login request
     * to proceed down the filter chain.
     *
     * <p>
     * If the login attempt exceeds the configured limits, the request
     * is short-circuited and a {@code 429} response is returned.
     * </p>
     */
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
                    "[RATE-LIMIT] Login blocked [strategy={}, retryAfter={}s]",
                    props.strategy(),
                    result.retryAfterSeconds());

            reject(response, request, result.retryAfterSeconds());
            return;
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Writes a standardized JSON error response when the rate limit
     * has been exceeded.
     *
     * @param response          HTTP response
     * @param request           originating HTTP request
     * @param retryAfterSeconds seconds until the next allowed attempt
     */
    private void reject(
            HttpServletResponse response,
            HttpServletRequest request,
            long retryAfterSeconds) throws IOException {

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());

        if (retryAfterSeconds > 0) {
            response.setHeader(
                    "Retry-After",
                    String.valueOf(retryAfterSeconds));
        }

        response.setContentType("application/json");

        ApiError error = errorFactory.create(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "Too many login attempts. Please try again later.",
                request);

        objectMapper.writeValue(response.getWriter(), error);
    }
}
