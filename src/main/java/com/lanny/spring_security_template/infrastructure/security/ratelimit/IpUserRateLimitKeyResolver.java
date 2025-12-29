package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

@Component
public class IpUserRateLimitKeyResolver implements RateLimitKeyResolver {

    @Override
    public String resolveKey(HttpServletRequest request) {

        String ip = resolveClientIp(request);
        String username = extractUsernameSafely(request);

        if (username == null || username.isBlank()) {
            return "IP:" + ip;
        }

        return "IP_USER:" + ip + "|" + hashUser(username);
    }

    // ======================================================
    // Helpers (PRIVATE)
    // ======================================================

    /**
     * Resolves the real client IP, considering reverse proxies / gateways.
     */
    private String resolveClientIp(HttpServletRequest request) {

        String xff = request.getHeader("X-Forwarded-For");
        if (xff != null && !xff.isBlank()) {
            // First IP = original client
            return xff.split(",")[0].trim();
        }

        return request.getRemoteAddr();
    }

    /**
     * Extracts username safely.
     *
     * NOTE:
     * - Works for form login / basic auth
     * - JSON login will return null (EXPECTED)
     */
    private String extractUsernameSafely(HttpServletRequest request) {
        return request.getParameter("username");
    }

    /**
     * Hashes username to avoid PII leakage.
     */
    private String hashUser(String username) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(username.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash)
                    .substring(0, 16); // short, stable, safe
        } catch (Exception e) {
            throw new IllegalStateException("Cannot hash username", e);
        }
    }
}
