package com.lanny.spring_security_template.infrastructure.security.filter;

import com.lanny.spring_security_template.infrastructure.security.handler.ApiError;
import com.lanny.spring_security_template.infrastructure.security.ratelimit.RateLimitKeyResolver;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Component
@Order(Ordered.HIGHEST_PRECEDENCE + 30)
public class LoginRateLimitingFilter extends OncePerRequestFilter {

    private final RateLimitingProperties props;
    private final RateLimitKeyResolver keyResolver;
    private final ObjectMapper objectMapper;
    private final AuthMetricsService metrics;

    private static final class Bucket {
        int attempts;
        Instant windowStart;
        Instant blockedUntil;
    }

    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    public LoginRateLimitingFilter(
            RateLimitingProperties props,
            RateLimitKeyResolver keyResolver,
            ObjectMapper objectMapper,
            AuthMetricsService metrics
    ) {
        this.props = props;
        this.keyResolver = keyResolver;
        this.objectMapper = objectMapper;
        this.metrics = metrics;
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        if (!props.enabled()) return true;

        // Solo aplica al endpoint y método configurado
        return !request.getRequestURI().equals(props.loginPath()) ||
                !"POST".equalsIgnoreCase(request.getMethod());
    }

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String key = keyResolver.resolveKey(request);
        Bucket bucket = buckets.computeIfAbsent(key, k -> {
            Bucket b = new Bucket();
            b.windowStart = Instant.now();
            return b;
        });

        Instant now = Instant.now();

        // Reset window
        if (bucket.windowStart.plusSeconds(props.window()).isBefore(now)) {
            bucket.windowStart = now;
            bucket.attempts = 0;
            bucket.blockedUntil = null;
        }

        // Blocked?
        if (bucket.blockedUntil != null && bucket.blockedUntil.isAfter(now)) {
            long retryAfter = bucket.blockedUntil.getEpochSecond() - now.getEpochSecond();
            reject(response, request, retryAfter, key);
            return;
        }

        // Attempt
        bucket.attempts++;

        if (bucket.attempts > props.maxAttempts()) {
            bucket.blockedUntil = now.plusSeconds(props.blockSeconds());
            long retryAfter = props.retryAfter();
            metrics.recordBruteForceDetected();
            logBruteForceEvent(key, request);
            reject(response, request, retryAfter, key);
            return;
        }

        filterChain.doFilter(request, response);
    }

    private void reject(HttpServletResponse response, HttpServletRequest request, long retryAfter, String key) throws IOException {
        response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
        response.setHeader("Retry-After", String.valueOf(retryAfter));
        response.setContentType("application/json");

        ApiError error = ApiError.of(
                HttpStatus.TOO_MANY_REQUESTS.value(),
                "Too many login attempts. Please try again later.",
                request
        );

        response.getWriter().write(objectMapper.writeValueAsString(error));
    }

    // logging del patrón por usuario + IP
    private void logBruteForceEvent(String key, HttpServletRequest request) {
        // Tu IpUserRateLimitKeyResolver construye: ip + "|" + username
        String ip = request.getRemoteAddr();
        String username = "unknown";

        if (key !=null && key.contains("|")) {
            String [] parts = key.split("\\|", 2);
            ip = parts[0];
            username = parts[1];            
        }
        // Aquí podrías usar SLF4J (si tienes @Slf4j) o logger normal
       System.out.printf(
                "[BRUTE-FORCE] Detected brute-force pattern for user='%s' from ip='%s'%n",
                username,
                ip
        );

    }
}

