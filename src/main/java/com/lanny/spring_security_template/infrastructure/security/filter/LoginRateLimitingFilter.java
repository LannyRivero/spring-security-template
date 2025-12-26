package com.lanny.spring_security_template.infrastructure.security.filter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.security.handler.ApiError;
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

@Slf4j
@Order(Ordered.HIGHEST_PRECEDENCE + 30)
public class LoginRateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitingProperties props;
    private final RateLimitKeyResolver keyResolver;
    private final ObjectMapper objectMapper;
    private final LoginAttemptPolicy loginAttemptPolicy;

    public LoginRateLimitingFilter(
            RateLimitingProperties props,
            RateLimitKeyResolver keyResolver,
            ObjectMapper objectMapper,
            LoginAttemptPolicy loginAttemptPolicy) {
        this.props = props;
        this.keyResolver = keyResolver;
        this.objectMapper = objectMapper;
        this.loginAttemptPolicy = loginAttemptPolicy;
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
            log.warn("[RATE-LIMIT] Login blocked for key={} retryAfter={}s",
                    key, result.retryAfterSeconds());

            reject(response, request, result.retryAfterSeconds());
            return;
        }

        filterChain.doFilter(request, response);
    }

    // ===================================
    // REJECT HANDLER
    // ===================================

    private void reject(
            HttpServletResponse response,
            HttpServletRequest request,
            long retryAfterSeconds) throws IOException {

        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());

        if (retryAfterSeconds > 0) {
            response.setHeader("Retry-After", String.valueOf(retryAfterSeconds));
        }

        response.setContentType("application/json");

        ApiError error = ApiError.of(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "Too many login attempts. Please try again later.",
                request);

        response.getWriter().write(
                objectMapper.writeValueAsString(error));
    }
}
