package com.lanny.spring_security_template.infrastructure.security.ssrf;

import java.net.InetAddress;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.UnknownHostException;

public class UrlSecurityValidator {

    public void validateOutboundUrl(String rawUrl) {
        URI uri = parseAndNormalize(rawUrl);

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

    private URI parseAndNormalize(String rawUrl) {
        try {
            return new URI(rawUrl).normalize();
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid URL format", e);
        }
    }

    private void validateHost(String host) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);

            for (InetAddress addr : addresses) {
                if (isPrivateOrLoopback(addr)) {
                    throw new IllegalArgumentException("Outbound calls to internal IPs are not allowed");
                }
            }
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException("Unknown host: " + host, e);
        }
    }

    private boolean isPrivateOrLoopback(InetAddress addr) {
        return addr.isAnyLocalAddress() // 0.0.0.0
                || addr.isLoopbackAddress() // 127.0.0.1, ::1
                || addr.isLinkLocalAddress() // 169.254.x.x
                || addr.isSiteLocalAddress(); // 10.x / 172.16.x / 192.168.x
    }
}
