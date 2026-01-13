package com.lanny.spring_security_template.infrastructure.security.filter;

import java.io.IOException;

import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * {@code SecurityHeadersFilter}
 *
 * <p>
 * Servlet filter responsible for applying a comprehensive set of
 * <b>HTTP security headers</b> to all HTTP responses.
 * </p>
 *
 * <p>
 * These headers provide browser-level hardening against common
 * web vulnerabilities such as XSS, clickjacking, MIME sniffing
 * and information leakage.
 * </p>
 *
 * <p>
 * Designed for <b>production-grade, enterprise APIs</b> and aligned
 * with OWASP ASVS and modern browser security recommendations.
 * </p>
 *
 * <p>
 * NOTE: Filter ordering is explicitly defined in {@code SecurityConfig}.
 * This filter must not declare its own {@code @Order}.
 * </p>
 */
@Component
public class SecurityHeadersFilter extends OncePerRequestFilter {

        /**
         * Strong default Content Security Policy suitable for REST APIs.
         *
         * <p>
         * Swagger UI or embedded consoles may require a relaxed CSP
         * in non-production environments.
         * </p>
         *
         * <p>
         * This value is intentionally strict and should only be overridden
         * via configuration, never weakened by default.
         * </p>
         */
        private static final String CSP_DEFAULT = "default-src 'self'; " +
                        "script-src 'self'; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:; " +
                        "font-src 'self'; " +
                        "object-src 'none'; " +
                        "base-uri 'self'; " +
                        "frame-ancestors 'none'; " +
                        "form-action 'self'";

        @Override
        protected void doFilterInternal(
                        @NonNull HttpServletRequest request,
                        @NonNull HttpServletResponse response,
                        @NonNull FilterChain filterChain)
                        throws ServletException, IOException {

                // Enforce HTTPS-only transport security when applicable
                // (avoid breaking local or non-TLS dev environments)
                if (request.isSecure()) {
                        setIfAbsent(
                                        response,
                                        "Strict-Transport-Security",
                                        "max-age=31536000; includeSubDomains; preload");
                }

                setIfAbsent(response, "X-Content-Type-Options", "nosniff");

                // Explicitly disable legacy XSS auditor (deprecated in modern browsers)
                setIfAbsent(response, "X-XSS-Protection", "0");

                setIfAbsent(response, "X-Frame-Options", "DENY");
                setIfAbsent(response, "Referrer-Policy", "no-referrer");

                setIfAbsent(
                                response,
                                "Permissions-Policy",
                                "geolocation=(), microphone=(), camera=(), payment=(), usb=()");

                setIfAbsent(response, "Cross-Origin-Opener-Policy", "same-origin");
                setIfAbsent(response, "Cross-Origin-Resource-Policy", "same-origin");
                setIfAbsent(response, "Content-Security-Policy", CSP_DEFAULT);

                // Prevent caching of sensitive responses
                setIfAbsent(response, "Cache-Control", "no-store, no-cache, must-revalidate");
                setIfAbsent(response, "Pragma", "no-cache");

                filterChain.doFilter(request, response);
        }

        private void setIfAbsent(HttpServletResponse response, String header, String value) {
                if (!response.containsHeader(header)) {
                        response.setHeader(header, value);
                }
        }
}
