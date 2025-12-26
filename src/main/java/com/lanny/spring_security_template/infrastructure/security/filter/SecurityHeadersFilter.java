package com.lanny.spring_security_template.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

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
 * web vulnerabilities such as:
 * </p>
 * <ul>
 * <li>Cross-Site Scripting (XSS)</li>
 * <li>Clickjacking</li>
 * <li>MIME type sniffing</li>
 * <li>Information leakage via referrers</li>
 * <li>Unintended browser feature access (camera, mic, etc.)</li>
 * </ul>
 *
 * <h2>Applied headers</h2>
 * <ul>
 * <li><b>Strict-Transport-Security (HSTS)</b> – enforced only over HTTPS</li>
 * <li><b>Content-Security-Policy (CSP)</b> – restricts resource loading</li>
 * <li><b>X-Content-Type-Options</b> – prevents MIME sniffing</li>
 * <li><b>X-Frame-Options</b> – protects against clickjacking</li>
 * <li><b>Referrer-Policy</b> – minimizes referrer information leakage</li>
 * <li><b>Permissions-Policy</b> – disables unnecessary browser features</li>
 * <li><b>Cross-Origin-Opener-Policy</b> and
 * <b>Cross-Origin-Resource-Policy</b> – enforces origin isolation</li>
 * </ul>
 *
 * <h2>Execution order</h2>
 * <p>
 * Executed with high precedence to ensure headers are applied consistently
 * to all responses, including error responses (401, 403, etc.).
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>No request path assumptions</li>
 * <li>Stateless and framework-agnostic</li>
 * <li>Safe for use behind gateways, reverse proxies and CDNs</li>
 * </ul>
 *
 * <p>
 * Designed for <b>production-grade, enterprise APIs</b> and aligned with
 * OWASP ASVS and modern browser security recommendations.
 * </p>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20)
public class SecurityHeadersFilter extends OncePerRequestFilter {

        /**
         * Strong Content Security Policy suitable for REST APIs and
         * back-office dashboards.
         *
         * <p>
         * Note: Swagger UI may require a relaxed CSP in non-production
         * environments.
         * </p>
         */
        private static final String CSP = "default-src 'self'; " +
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
                        @NonNull FilterChain filterChain) throws ServletException, IOException {

                // Enforce HTTPS only when the request is secure (avoid breaking dev / HTTP)
                if (request.isSecure()) {
                        response.setHeader(
                                        "Strict-Transport-Security",
                                        "max-age=31536000; includeSubDomains; preload");
                }

                // Prevent MIME sniffing
                response.setHeader("X-Content-Type-Options", "nosniff");

                // Explicitly disable legacy XSS protection mechanisms
                response.setHeader("X-XSS-Protection", "0");

                // Prevent clickjacking
                response.setHeader("X-Frame-Options", "DENY");

                // Minimize referrer information leakage
                response.setHeader("Referrer-Policy", "no-referrer");

                // Disable unnecessary browser features
                response.setHeader(
                                "Permissions-Policy",
                                "geolocation=(), microphone=(), camera=(), payment=(), usb=()");

                // Enforce origin isolation
                response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
                response.setHeader("Cross-Origin-Resource-Policy", "same-origin");

                // Apply Content Security Policy
                response.setHeader("Content-Security-Policy", CSP);

                filterChain.doFilter(request, response);
        }
}
