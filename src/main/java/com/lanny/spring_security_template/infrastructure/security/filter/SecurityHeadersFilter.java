package com.lanny.spring_security_template.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;

/**
 * Adds standard security HTTP headers to prevent XSS, clickjacking, and data
 * leakage.
 * Automatically relaxes CSP for Swagger UI and API docs in dev/test
 * environments only.
 */
@Order(FilterOrder.SECURITY_HEADERS)
@Component
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private final Environment env;

    @Value("${security.headers.content-security-policy:default-src 'none'; frame-ancestors 'none';}")
    private String defaultCsp;

    @Value("${security.headers.referrer-policy:no-referrer}")
    private String referrer;

    public SecurityHeadersFilter(Environment env) {
        this.env = env;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest req,
            @NonNull HttpServletResponse res,
            @NonNull FilterChain chain) throws ServletException, IOException {

        String uri = req.getRequestURI();
        String[] activeProfiles = env.getActiveProfiles();
        boolean isDevOrTest = Arrays.stream(activeProfiles)
                .anyMatch(p -> p.equalsIgnoreCase("dev") || p.equalsIgnoreCase("test"));

        if (isDevOrTest && (uri.startsWith("/swagger-ui") || uri.startsWith("/v3/api-docs"))) {
            res.setHeader("Content-Security-Policy",
                    "default-src 'self'; " +
                            "img-src 'self' data:; " +
                            "style-src 'self' 'unsafe-inline'; " +
                            "script-src 'self' 'unsafe-inline' 'unsafe-eval';");
        } else {
            res.setHeader("Content-Security-Policy", defaultCsp);
        }

        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("X-XSS-Protection", "0");
        res.setHeader("Referrer-Policy", referrer);

        chain.doFilter(req, res);
    }
}
