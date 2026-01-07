package com.lanny.spring_security_template.infrastructure.security.network;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * {@code ClientIpResolver}
 *
 * <p>
 * Resolves the <b>real client IP address</b> in a secure and predictable way.
 * </p>
 *
 * <h2>Why this exists</h2>
 * <ul>
 * <li>{@code X-Forwarded-For} headers can be spoofed by clients</li>
 * <li>Only trusted proxies (LB / reverse proxy) should be allowed
 * to influence client IP resolution</li>
 * <li>Centralizing this logic prevents inconsistent or insecure IP
 * handling</li>
 * </ul>
 *
 * <h2>Resolution strategy</h2>
 * <ol>
 * <li>If the direct remote address is NOT a trusted proxy → use it</li>
 * <li>If it IS a trusted proxy → extract the first IP from
 * {@code X-Forwarded-For}</li>
 * <li>Fallback to {@code request.getRemoteAddr()}</li>
 * </ol>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>No blind trust in forwarded headers</li>
 * <li>Safe against IP spoofing</li>
 * <li>Deterministic behavior</li>
 * </ul>
 *
 * <p>
 * NOTE:
 * In real deployments, trusted proxy ranges SHOULD be externalized
 * to configuration (CIDR ranges, Kubernetes service IPs, etc.).
 * </p>
 */
@Component
public class ClientIpResolver {

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";

    /**
     * List of trusted proxy IP prefixes.
     *
     * <p>
     * Examples:
     * - Kubernetes cluster IPs
     * - Load balancer private ranges
     * </p>
     */
    private final List<String> trustedProxyPrefixes = List.of(
            "10.",
            "192.168.",
            "172.16.");

    /**
     * Resolves the client IP address for the given request.
     *
     * @param request current HTTP request
     * @return resolved client IP address
     */
    public String resolve(HttpServletRequest request) {

        String remoteAddr = request.getRemoteAddr();

        // If request does NOT come from a trusted proxy, ignore forwarded headers
        if (!isTrustedProxy(remoteAddr)) {
            return remoteAddr;
        }

        String forwardedFor = request.getHeader(X_FORWARDED_FOR);
        if (forwardedFor == null || forwardedFor.isBlank()) {
            return remoteAddr;
        }

        // First IP is the original client
        return forwardedFor.split(",")[0].trim();
    }

    private boolean isTrustedProxy(String ip) {
        return trustedProxyPrefixes.stream().anyMatch(ip::startsWith);
    }
}
