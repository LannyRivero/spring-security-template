package com.lanny.spring_security_template.infrastructure.http;

import org.springframework.stereotype.Component;

import java.net.URI;

@Component
public class UrlSecurityValidator {

    public void validate(URI uri) {
        String scheme = uri.getScheme();
        if (!("http".equalsIgnoreCase(scheme) || "https".equalsIgnoreCase(scheme))) {
            throw new IllegalArgumentException("Invalid URL scheme: " + scheme);
        }

        String host = uri.getHost();
        if (host == null) {
            throw new IllegalArgumentException("URL host cannot be null.");
        }

        if (host.equals("localhost") ||
            host.startsWith("127.") ||
            host.startsWith("10.") ||
            host.startsWith("192.168.") ||
            host.startsWith("169.254.")) {

            throw new IllegalArgumentException("Blocked internal/loopback host: " + host);
        }
    }
}

