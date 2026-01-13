package com.lanny.spring_security_template.infrastructure.security.ssrf;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * ============================================================
 * UrlSecurityValidator
 * ============================================================
 *
 * <p>
 * Stateless validator enforcing outbound URL security rules to mitigate
 * Server-Side Request Forgery (SSRF) attacks.
 * </p>
 *
 * <h2>Threat model</h2>
 * <p>
 * This validator prevents the application from issuing outbound HTTP(S)
 * requests to internal, loopback or otherwise non-public network addresses.
 * </p>
 *
 * <h2>Validation rules</h2>
 * <ul>
 * <li>Only absolute {@code http} and {@code https} URIs are allowed</li>
 * <li>A non-blank host must be present</li>
 * <li>All resolved IP addresses must be publicly routable</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>DNS resolution is performed explicitly to detect internal addresses</li>
 * <li>All resolved addresses must be safe (no partial acceptance)</li>
 * <li>This class performs validation only and never executes requests</li>
 * </ul>
 *
 * <p>
 * This component is intended to be used before any outbound HTTP client
 * invocation.
 * </p>
 */
public class UrlSecurityValidator {

    /**
     * Validates an outbound destination URI.
     *
     * @param uri the target URI to validate (must be absolute)
     * @throws IllegalArgumentException if the URI is unsafe or invalid
     */
    public void validate(URI uri) {

        if (uri == null) {
            throw new IllegalArgumentException("URI must not be null");
        }

        if (!uri.isAbsolute()) {
            throw new IllegalArgumentException("Only absolute URIs are allowed");
        }

        String scheme = uri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("Unsupported URI scheme");
        }

        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("URI must contain a valid host");
        }

        validateHostResolution(host);
    }

    private void validateHostResolution(String host) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);

            for (InetAddress address : addresses) {
                if (isUnsafeAddress(address)) {
                    throw new IllegalArgumentException(
                            "Outbound request target is not allowed");
                }
            }

        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException("Unknown host", ex);
        }
    }

    private boolean isUnsafeAddress(InetAddress address) {
        return address.isAnyLocalAddress() // 0.0.0.0
                || address.isLoopbackAddress() // 127.0.0.1, ::1
                || address.isLinkLocalAddress()// 169.254.x.x
                || address.isSiteLocalAddress()// 10.x / 172.16.x / 192.168.x
                || address.isMulticastAddress();// 224.0.0.0/4, ff00::/8
    }
}
