package com.lanny.spring_security_template.infrastructure.security.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 *  Simple rate limiting filter for /api/v1/auth/login endpoint.
 * Blocks brute-force attempts using a per-IP sliding window counter.
 */
@Order(FilterOrder.RATE_LIMITING)
@Component
public class LoginRateLimitingFilter extends OncePerRequestFilter {

    private static final String LOGIN_PATH = "/api/v1/auth/login";

    @Value("${security.rate-limit.max-requests:5}")
    private int maxRequests;

    @Value("${security.rate-limit.window-seconds:60}")
    private long windowSeconds;
    private final Map<String, SlidingWindow> buckets = new ConcurrentHashMap<>();

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest req,
            @NonNull HttpServletResponse res,
            @NonNull FilterChain chain) throws ServletException, IOException {
        if (req.getRequestURI().startsWith(LOGIN_PATH)) {
            String key = clientKey(req);
            SlidingWindow window = buckets.computeIfAbsent(key, k -> new SlidingWindow());

            if (!window.tryAcquire(maxRequests, windowSeconds)) {
                res.setStatus(429);
                res.setHeader("Retry-After", String.valueOf(windowSeconds));
                res.getWriter().write("Too Many Requests");
                return;
            }
        }

        chain.doFilter(req, res);
    }

    private String clientKey(HttpServletRequest req) {
        // Use remote address directly to prevent spoofing
        // If behind a trusted proxy, configure your proxy to set a different header
        return req.getRemoteAddr();
    }

    /** Sliding window algorithm (per IP). */
    static class SlidingWindow {
        private final Deque<Long> events = new ArrayDeque<>();

        synchronized boolean tryAcquire(int max, long windowSec) {
            long now = Instant.now().getEpochSecond();

            // remove old timestamps
            while (!events.isEmpty() && now - events.peekFirst() >= windowSec) {
                events.pollFirst();
            }

            if (events.size() >= max)
                return false;
            events.addLast(now);
            return true;
        }
    }
}
