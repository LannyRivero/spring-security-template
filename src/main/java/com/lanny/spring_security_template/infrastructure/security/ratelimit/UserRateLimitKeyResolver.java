package com.lanny.spring_security_template.infrastructure.security.ratelimit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * ============================================================
 * UserRateLimitKeyResolver
 * ============================================================
 *
 * <p>
 * {@link RateLimitKeyResolver} implementation that derives rate-limiting
 * keys based <b>exclusively on the username</b>.
 * </p>
 *
 * <h2>Intended usage</h2>
 * <p>
 * This strategy is designed for <b>controlled environments</b> where:
 * </p>
 * <ul>
 * <li>Client IP addresses are unreliable or frequently shared
 * (e.g. corporate proxies, NAT gateways)</li>
 * <li>User identity is the primary signal for abuse detection</li>
 * <li>Authentication endpoints are already protected by
 * additional controls (CAPTCHA, MFA, device fingerprinting)</li>
 * </ul>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Usernames are <b>never stored or exposed in clear text</b></li>
 * <li>Derived keys are deterministic and stable</li>
 * <li>Anonymous or missing usernames are mapped to a safe fallback</li>
 * </ul>
 *
 * <h2>Important warning</h2>
 * <p>
 * This resolver should <b>NOT</b> be the default choice for public-facing
 * authentication endpoints.
 * </p>
 *
 * <p>
 * Without an IP component, this strategy may be vulnerable to
 * distributed credential-stuffing attacks unless combined with
 * complementary protections.
 * </p>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>No request body parsing</li>
 * <li>No side effects</li>
 * <li>Fail-safe by design: hashing errors never block authentication</li>
 * </ul>
 */
@Component
public class UserRateLimitKeyResolver implements RateLimitKeyResolver {

    /**
     * Namespaced Redis-safe key prefix.
     *
     * <pre>
     * security:ratelimit:v1:user:{hash}
     * </pre>
     */
    private static final String KEY_PREFIX = "security:ratelimit:v1:user:";

    @Override
    public String resolveKey(HttpServletRequest request) {

        String user = request.getParameter("username");

        if (user == null || user.isBlank()) {
            return KEY_PREFIX + "anonymous";
        }

        return KEY_PREFIX + hashUser(user);
    }

    /**
     * Hashes the username to avoid storing PII in rate-limiting keys.
     *
     * <p>
     * Uses SHA-256 and truncates the output for compactness while
     * preserving sufficient entropy.
     * </p>
     *
     * <p>
     * Fail-safe behavior: any hashing failure results in a deterministic
     * non-PII fallback value.
     * </p>
     */
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
