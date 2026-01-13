package com.lanny.spring_security_template.infrastructure.security.network;

import java.net.InetAddress;
import java.net.UnknownHostException;

import org.springframework.stereotype.Component;

import jakarta.servlet.http.HttpServletRequest;

/**
 * ============================================================
 * ClientIpResolver
 * ============================================================
 *
 * <p>
 * Resolves the effective client IP address in a secure, deterministic
 * and fail-safe manner.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>{@code X-Forwarded-For} is trusted <b>only</b> when the immediate
 * sender is a configured trusted proxy</li>
 * <li>Trusted proxies are defined using CIDR notation (IPv4 / IPv6)</li>
 * <li>Never returns {@code null}</li>
 * <li>Never throws exceptions</li>
 * <li>Always falls back to {@link HttpServletRequest#getRemoteAddr()}</li>
 * </ul>
 *
 * <h2>Threat model</h2>
 * <ul>
 * <li>Prevents client-controlled IP spoofing</li>
 * <li>Prevents rate-limiting bypass via fake headers</li>
 * <li>Safe to use before authentication</li>
 * </ul>
 */
@Component
public class ClientIpResolver {

    private static final String X_FORWARDED_FOR = "X-Forwarded-For";

    private final NetworkSecurityProperties props;

    public ClientIpResolver(NetworkSecurityProperties props) {
        this.props = props;
    }

    /**
     * Resolves the client IP address for the given request.
     *
     * <p>
     * This method is fail-safe by design and never throws.
     * </p>
     *
     * @param request incoming HTTP request (never {@code null})
     * @return a non-null, normalized client IP address
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

        String candidate = forwardedFor.split(",")[0].trim();

        return isValidIp(candidate) ? candidate : remoteAddr;
    }

    /**
     * Determines whether the given IP belongs to a trusted proxy.
     */
    private boolean isTrustedProxy(String ip) {
        return props.trustedProxyCidrs().stream()
                .anyMatch(cidr -> matchesCidr(cidr, ip));
    }

    /**
     * Validates that a string represents a valid IPv4 or IPv6 address.
     */
    private boolean isValidIp(String ip) {
        try {
            InetAddress.getByName(ip);
            return true;
        } catch (UnknownHostException ex) {
            return false;
        }
    }

    /**
     * Checks whether the given IP matches a CIDR range.
     *
     * <p>
     * Fail-safe: returns {@code false} on any parsing or format error.
     * </p>
     */
    private boolean matchesCidr(String cidr, String ip) {
        try {
            String[] parts = cidr.split("/");
            InetAddress cidrAddress = InetAddress.getByName(parts[0]);
            InetAddress ipAddress = InetAddress.getByName(ip);

            int prefixLength = Integer.parseInt(parts[1]);

            byte[] cidrBytes = cidrAddress.getAddress();
            byte[] ipBytes = ipAddress.getAddress();

            if (cidrBytes.length != ipBytes.length) {
                return false; // IPv4 vs IPv6 mismatch
            }

            int fullBytes = prefixLength / 8;
            int remainingBits = prefixLength % 8;

            for (int i = 0; i < fullBytes; i++) {
                if (cidrBytes[i] != ipBytes[i]) {
                    return false;
                }
            }

            if (remainingBits > 0) {
                int mask = (-1) << (8 - remainingBits);
                return (cidrBytes[fullBytes] & mask) == (ipBytes[fullBytes] & mask);
            }

            return true;

        } catch (Exception ex) {
            return false;
        }
    }
}
