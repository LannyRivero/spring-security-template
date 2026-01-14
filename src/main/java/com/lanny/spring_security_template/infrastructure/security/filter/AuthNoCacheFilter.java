package com.lanny.spring_security_template.infrastructure.security.filter;

import java.io.IOException;

import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * ============================================================
 * AuthNoCacheFilter
 * ============================================================
 *
 * <p>
 * Enforces strict no-cache HTTP headers on responses generated
 * for authenticated requests only.
 * </p>
 *
 * <h2>Purpose</h2>
 * <p>
 * Prevents sensitive data returned by protected endpoints
 * (profiles, tokens, personal information, etc.)
 * from being cached by browsers, proxies or intermediate caches.
 * </p>
 *
 * <h2>Scope</h2>
 * <ul>
 * <li>Applied only when a user is authenticated</li>
 * <li>Public and unauthenticated endpoints are excluded</li>
 * <li>No path-based assumptions are made</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No-store policy for authenticated responses</li>
 * <li>Prevents back/forward cache leakage after logout</li>
 * <li>Compliant with OWASP REST security recommendations</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Stateless and side-effect free</li>
 * <li>Does not alter response status or body</li>
 * <li>Safe for use behind gateways, CDNs and reverse proxies</li>
 * </ul>
 */
@Order(FilterOrder.AUTH_NO_CACHE)
@Component
public class AuthNoCacheFilter extends OncePerRequestFilter {

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        // Apply only to authenticated requests
        return request.getUserPrincipal() == null;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest req,
            @NonNull HttpServletResponse res,
            @NonNull FilterChain chain)
            throws ServletException, IOException {

        // Enforce no-cache semantics for authenticated responses
        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        res.setHeader("Pragma", "no-cache");
        res.setHeader("Expires", "0");

        chain.doFilter(req, res);
    }
}
