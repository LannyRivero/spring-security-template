package com.lanny.spring_security_template.infrastructure.security.ssrf;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * UrlSecurityValidator
 *
 * Enforces outbound URL security rules to prevent SSRF attacks.
 *
 * This class validates:
 * - Allowed schemes (http / https)
 * - Presence of a valid host
 * - Resolution of host to public (non-internal) IP addresses
 *
 * Stateless and reusable.
 */
public class UrlSecurityValidator {

    /**
     * Validates an outbound destination URI.
     *
     * @param uri normalized target URI
     * @throws IllegalArgumentException if destination is unsafe
     */
    public void validate(URI uri) {

        if (uri == null) {
            throw new IllegalArgumentException("URI must not be null");
        }

        String scheme = uri.getScheme();
        if (scheme == null || !(scheme.equalsIgnoreCase("http") || scheme.equalsIgnoreCase("https"))) {
            throw new IllegalArgumentException("Unsupported URL scheme: " + scheme);
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("URL must contain a valid host");
        }

        validateHost(host);
    }

    private void validateHost(String host) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);

            for (InetAddress addr : addresses) {
                if (isPrivateOrLoopback(addr)) {
                    throw new IllegalArgumentException(
                            "Outbound calls to internal IPs are not allowed: " + addr.getHostAddress());
                }
            }
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Unknown host: " + host, e);
        }
    }

    private boolean isPrivateOrLoopback(InetAddress addr) {
        return addr.isAnyLocalAddress() // 0.0.0.0
                || addr.isLoopbackAddress() // 127.0.0.1, ::1
                || addr.isLinkLocalAddress()// 169.254.x.x
                || addr.isSiteLocalAddress();// 10.x / 172.16.x / 192.168.x
    }
}
