package com.lanny.spring_security_template.infrastructure.security.network;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * {@code ClientIpResolver}
 *
 * <p>
 * Resolves the real client IP address in a secure, deterministic way.
 * </p>
 *
 * <h2>Security rationale</h2>
 * <ul>
 * <li>{@code X-Forwarded-For} can be spoofed by clients</li>
 * <li>Only trusted proxies may influence IP resolution</li>
 * <li>Centralized logic prevents inconsistent behavior</li>
 * </ul>
 *
 * <h2>Resolution strategy</h2>
 * <ol>
 * <li>If the remote address is NOT a trusted proxy → use it</li>
 * <li>If it IS a trusted proxy → extract first IP from X-Forwarded-For</li>
 * <li>Fallback to {@code request.getRemoteAddr()}</li>
 * </ol>
 */
@Component
public class ClientIpResolver {

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";

    private final NetworkSecurityProperties props;

    public ClientIpResolver(NetworkSecurityProperties props) {
        this.props = props;
    }

    /**
     * Resolves the client IP for the given request.
     *
     * @param request HTTP request
     * @return resolved client IP address
     */
    public String resolve(HttpServletRequest request) {

        String remoteAddr = request.getRemoteAddr();

        if (!isTrustedProxy(remoteAddr)) {
            return remoteAddr;
        }

        String forwardedFor = request.getHeader(X_FORWARDED_FOR);
        if (forwardedFor == null || forwardedFor.isBlank()) {
            return remoteAddr;
        }

        return forwardedFor.split(",")[0].trim();
    }

    private boolean isTrustedProxy(String ip) {
        return props.trustedProxyPrefixes().stream()
                .anyMatch(ip::startsWith);
    }
}
