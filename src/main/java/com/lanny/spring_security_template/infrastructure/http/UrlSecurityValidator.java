package com.lanny.spring_security_template.infrastructure.http;

import org.springframework.stereotype.Component;

import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;

/**
 * UrlSecurityValidator
 *
 * Enterprise-grade outbound URL validator.
 *
 * Responsibilities:
 * - Prevent SSRF attacks by validating final resolved destinations
 * - Enforce allowed schemes (http / https)
 * - Block private, loopback, link-local and internal addresses
 *
 * IMPORTANT:
 * - This validator resolves DNS and validates ALL resolved IPs
 * - Security is enforced on the destination, not the hostname
 *
 * This class is designed to be:
 * - Secure by default
 * - Configurable by extension (allow-lists, mTLS, etc.)
 */
@Component
public class UrlSecurityValidator {

    public void validate(URI uri) {

        validateScheme(uri);
        validateHost(uri);
        validateResolvedAddresses(uri.getHost());
    }

    private void validateScheme(URI uri) {
        String scheme = uri.getScheme();
        if (!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme)) {
            throw new IllegalArgumentException("Blocked URL scheme: " + scheme);
        }
    }

    private void validateHost(URI uri) {
        String host = uri.getHost();
        if (host == null || host.isBlank()) {
            throw new IllegalArgumentException("URL host is missing");
        }
    }

    private void validateResolvedAddresses(String host) {
        try {
            InetAddress[] addresses = InetAddress.getAllByName(host);

            for (InetAddress addr : addresses) {
                if (isBlockedAddress(addr)) {
                    throw new IllegalArgumentException(
                        "Blocked outbound destination: " + addr.getHostAddress());
                }
            }

        } catch (UnknownHostException ex) {
            throw new IllegalArgumentException(
                "Unable to resolve host: " + host, ex);
        }
    }

    /**
     * Blocks all non-public addresses.
     *
     * This includes:
     * - loopback
     * - link-local
     * - site-local (RFC1918)
     * - multicast
     * - CGNAT
     * - IPv6 unique local addresses
     */
    private boolean isBlockedAddress(InetAddress addr) {

        return addr.isAnyLocalAddress()
                || addr.isLoopbackAddress()
                || addr.isLinkLocalAddress()
                || addr.isSiteLocalAddress()
                || addr.isMulticastAddress()
                || isCgnat(addr)
                || isIpv6UniqueLocal(addr);
    }

    /**
     * 100.64.0.0/10 — Carrier Grade NAT
     */
    private boolean isCgnat(InetAddress addr) {
        byte[] ip = addr.getAddress();
        return ip.length == 4
                && (ip[0] & 0xFF) == 100
                && (ip[1] & 0xC0) == 64;
    }

    /**
     * IPv6 Unique Local Addresses (fc00::/7)
     */
    private boolean isIpv6UniqueLocal(InetAddress addr) {
        byte[] ip = addr.getAddress();
        return ip.length == 16
                && (ip[0] & 0xFE) == 0xFC;
    }
}

