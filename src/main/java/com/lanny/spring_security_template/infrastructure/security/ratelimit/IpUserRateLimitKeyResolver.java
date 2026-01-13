package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.security.network.ClientIpResolver;

import jakarta.servlet.http.HttpServletRequest;

/**
 * ============================================================
 * IpUserRateLimitKeyResolver
 * ============================================================
 *
 * <p>
 * Builds deterministic rate-limiting keys based on the resolved client IP
 * address and, when available, a hashed username.
 * </p>
 *
 * <h2>Key strategy</h2>
 * <ul>
 * <li>IP-only key when username is unavailable</li>
 * <li>IP + hashed username when username is present</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No blind trust in forwarded headers (delegated to
 * {@link ClientIpResolver})</li>
 * <li>No PII leakage (usernames are hashed)</li>
 * <li>Fail-safe behavior: key resolution never blocks authentication</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>This resolver does not parse request bodies</li>
 * <li>JSON-based login flows are expected to fall back to IP-only limiting</li>
 * <li>Errors during hashing never propagate</li>
 * </ul>
 */
@Component
public class IpUserRateLimitKeyResolver implements RateLimitKeyResolver {

    private static final String KEY_PREFIX = "security:ratelimit:v1:";

    private final ClientIpResolver ipResolver;

    public IpUserRateLimitKeyResolver(ClientIpResolver ipResolver) {
        this.ipResolver = ipResolver;
    }

    @Override
    public String resolveKey(HttpServletRequest request) {

        String ip = ipResolver.resolve(request);
        String username = extractUsernameSafely(request);

        if (username == null) {
            return KEY_PREFIX + "ip:" + ip;
        }

        return KEY_PREFIX + "ip-user:" + ip + ":" + hashUser(username);
    }

    private String extractUsernameSafely(HttpServletRequest request) {
        String raw = request.getParameter("username");
        if (raw == null) {
            return null;
        }
        String normalized = raw.trim();
        return normalized.isEmpty() ? null : normalized;
    }

    private String hashUser(String username) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(username.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder()
                    .withoutPadding()
                    .encodeToString(hash)
                    .substring(0, 16);
        } catch (Exception ex) {
            return "hash_error";
        }
    }
}
