package com.lanny.spring_security_template.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/**
 * Adds standard security HTTP headers to prevent XSS, clickjacking, and data leakage.
 */
@Component
public class SecurityHeadersFilter extends OncePerRequestFilter {

    @Value("${security.headers.content-security-policy:default-src 'none'; frame-ancestors 'none';}")
    private String csp;

    @Value("${security.headers.referrer-policy:no-referrer}")
    private String referrer;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest req,
            @NonNull HttpServletResponse res,
            @NonNull FilterChain chain
    ) throws ServletException, IOException {

        res.setHeader("X-Content-Type-Options", "nosniff");
        res.setHeader("X-Frame-Options", "DENY");
        res.setHeader("X-XSS-Protection", "0"); 
        res.setHeader("Referrer-Policy", referrer);
        res.setHeader("Content-Security-Policy", csp);

        chain.doFilter(req, res);
    }
}