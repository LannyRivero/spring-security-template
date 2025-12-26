package com.lanny.spring_security_template.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

/**
 * {@code AuthNoCacheFilter}
 *
 * <p>
 * Servlet filter that enforces <b>no-cache HTTP headers</b> on
 * <b>authenticated responses only</b>.
 * </p>
 *
 * <p>
 * This filter prevents sensitive data returned by protected endpoints
 * (e.g. user profiles, tokens, personal information) from being cached by:
 * </p>
 * <ul>
 * <li>Web browsers (including back/forward cache)</li>
 * <li>Intermediate HTTP proxies</li>
 * <li>Shared or private caches</li>
 * </ul>
 *
 * <h2>Scope</h2>
 * <p>
 * The filter is intentionally applied <b>only</b> when a user is authenticated.
 * Public and unauthenticated endpoints (such as health checks, OpenAPI,
 * or static resources) are excluded to avoid unnecessary performance impact.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Prevents caching of sensitive authenticated responses</li>
 * <li>Reduces risk of data leakage after logout or session termination</li>
 * <li>Complies with OWASP recommendations for REST API security</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>No hardcoded paths or resource assumptions</li>
 * <li>Relies on {@code SecurityContext} state rather than request URIs</li>
 * <li>Safe for use behind API gateways, CDNs and reverse proxies</li>
 * </ul>
 *
 * <p>
 * This filter is designed for <b>stateless, JWT-based APIs</b> and is suitable
 * for enterprise and regulated environments.
 * </p>
 */

@Order(FilterOrder.AUTH_NO_CACHE)
@Component
public class AuthNoCacheFilter extends OncePerRequestFilter {

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {

        return request.getUserPrincipal() == null;
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest req,
            @NonNull HttpServletResponse res,
            @NonNull FilterChain chain) throws ServletException, IOException {

        res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
        res.setHeader("Pragma", "no-cache");

        chain.doFilter(req, res);
    }
}
