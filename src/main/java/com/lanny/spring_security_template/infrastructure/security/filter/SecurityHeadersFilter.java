package com.lanny.spring_security_template.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.lang.NonNull;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 20) 
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private static final String CSP =
            "default-src 'self'; " +
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
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        //  Sólo tiene sentido HSTS si estás detrás de HTTPS en prod
        response.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload");

        // Anti XSS / MIME sniffing
        response.setHeader("X-Content-Type-Options", "nosniff");
        response.setHeader("X-XSS-Protection", "0"); 

        // Clickjacking
        response.setHeader("X-Frame-Options", "DENY");

        // Referrer minimizado
        response.setHeader("Referrer-Policy", "no-referrer");

        // Permissions-Policy (antes Feature-Policy)
        response.setHeader("Permissions-Policy",
                "geolocation=(), microphone=(), camera=(), payment=(), usb=()");

        // COOP / CORP → asilamiento de contexto (bueno para SPAs, dashboards, etc.)
        response.setHeader("Cross-Origin-Opener-Policy", "same-origin");
        response.setHeader("Cross-Origin-Resource-Policy", "same-origin");

        // CSP fuerte pero compatible con API REST + Swagger
        response.setHeader("Content-Security-Policy", CSP);

        filterChain.doFilter(request, response);
    }
}

