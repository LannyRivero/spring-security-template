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
 * ============================================================
 * SecurityHeadersFilter
 * ============================================================
 *
 * <p>
 * Servlet filter responsible for applying a comprehensive set of
 * HTTP security headers to all HTTP responses.
 * </p>
 *
 * <h2>Scope</h2>
 * <ul>
 * <li>Applies to all responses (authenticated and unauthenticated)</li>
 * <li>Stateless and idempotent</li>
 * <li>Does not depend on authentication state</li>
 * </ul>
 *
 * <h2>Security goals</h2>
 * <ul>
 * <li>Mitigate XSS and injection attacks</li>
 * <li>Prevent clickjacking and UI redressing</li>
 * <li>Disable MIME sniffing</li>
 * <li>Reduce information leakage via referrers</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Headers are only set if absent to remain compatible with gateways</li>
 * <li>Cache-control is handled by {@link AuthNoCacheFilter}</li>
 * <li>No environment-specific logic is embedded</li>
 * </ul>
 */
@Component
public class SecurityHeadersFilter extends OncePerRequestFilter {

        /**
         * Strong default Content Security Policy suitable for REST APIs.
         *
         * <p>
         * Note: {@code frame-ancestors 'none'} supersedes {@code X-Frame-Options}.
         * The latter is still sent for legacy browser compatibility.
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

                if (request.isSecure()) {
                        setIfAbsent(
                                        response,
                                        "Strict-Transport-Security",
                                        "max-age=31536000; includeSubDomains; preload");
                }

                setIfAbsent(response, "X-Content-Type-Options", "nosniff");
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

                filterChain.doFilter(request, response);
        }

        private void setIfAbsent(HttpServletResponse response, String header, String value) {
                if (!response.containsHeader(header)) {
                        response.setHeader(header, value);
                }
        }
}
