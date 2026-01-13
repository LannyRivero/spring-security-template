package com.lanny.spring_security_template.infrastructure.security.network;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

import java.net.InetAddress;

/**
 * {@code ClientIpResolver}
 *
 * Resolves the real client IP address in a secure and deterministic way.
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>X-Forwarded-For is only trusted when the remote address is a trusted
 * proxy</li>
 * <li>Trusted proxies are defined using CIDR ranges (IPv4 / IPv6)</li>
 * <li>Fallback is always {@code request.getRemoteAddr()}</li>
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

    /**
     * Determines whether the given IP address belongs to a trusted proxy.
     *
     * Trusted proxies are defined using CIDR notation (e.g. 10.0.0.0/8).
     */
    private boolean isTrustedProxy(String ip) {
        return props.trustedProxyCidrs().stream()
                .anyMatch(cidr -> matchesCidr(cidr, ip));
    }

    /**
     * Checks whether the given IP matches the provided CIDR range.
     *
     * Fail-safe: returns false if parsing fails.
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
