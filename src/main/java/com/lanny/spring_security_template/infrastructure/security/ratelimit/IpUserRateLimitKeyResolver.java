package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import com.lanny.spring_security_template.infrastructure.security.network.ClientIpResolver;

/**
 * {@code IpUserRateLimitKeyResolver}
 *
 * <p>
 * Builds rate-limiting keys based on a combination of:
 * </p>
 * <ul>
 * <li>Resolved client IP address</li>
 * <li>Username (hashed, when available)</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No blind trust in forwarded headers</li>
 * <li>No PII leakage (hashed usernames)</li>
 * <li>Consistent IP resolution across the system</li>
 * </ul>
 */
@Component
public class IpUserRateLimitKeyResolver implements RateLimitKeyResolver {

    private final ClientIpResolver ipResolver;

    public IpUserRateLimitKeyResolver(ClientIpResolver ipResolver) {
        this.ipResolver = ipResolver;
    }

    @Override
    public String resolveKey(HttpServletRequest request) {

        String ip = ipResolver.resolve(request);
        String username = extractUsernameSafely(request);

        if (username == null || username.isBlank()) {
            return "IP:" + ip;
        }

        return "IP_USER:" + ip + "|" + hashUser(username);
    }

    // ======================================================
    // Helpers
    // ======================================================

    /**
     * Extracts username safely from request parameters.
     *
     * <p>
     * NOTE:
     * <ul>
     * <li>Works for form-based login</li>
     * <li>Returns null for JSON-based login (EXPECTED)</li>
     * </ul>
     * </p>
     */
    private String extractUsernameSafely(HttpServletRequest request) {
        return request.getParameter("username");
    }

    /**
     * Hashes username to avoid PII leakage while keeping
     * rate-limiting keys stable.
     */
    private String hashUser(String username) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(username.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash)
                    .substring(0, 16);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot hash username for rate limiting", e);
        }
    }
}
