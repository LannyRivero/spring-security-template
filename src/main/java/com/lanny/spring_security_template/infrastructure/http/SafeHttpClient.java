package com.lanny.spring_security_template.infrastructure.http;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Objects;

/**
 * SafeHttpClient
 *
 * Infrastructure adapter that encapsulates outbound HTTP calls.
 *
 * Responsibilities:
 * - Centralize outbound HTTP usage
 * - Enforce destination validation (SSRF protection)
 * - Prevent direct RestTemplate usage in upper layers
 *
 * IMPORTANT:
 * - This class does NOT implement security policies itself.
 * - All destination security rules are delegated to UrlSecurityValidator.
 *
 * This design keeps transport concerns separate from security policy.
 */
@Component
public class SafeHttpClient {

    private final RestTemplate restTemplate;
    private final UrlSecurityValidator validator;

    public SafeHttpClient(RestTemplate restTemplate, UrlSecurityValidator validator) {
        this.restTemplate = restTemplate;
        this.validator = validator;
    }

    public <T> T get(String url, Class<T> responseType) {

        Objects.requireNonNull(url, "url must not be null");
        Objects.requireNonNull(responseType, "responseType must not be null");

        URI uri = parseUri(url);
        validator.validate(uri);

        return restTemplate.getForObject(Objects.requireNonNull(uri), responseType);
    }

    public <T> T post(String url, Object body, Class<T> responseType) {

        Objects.requireNonNull(url, "url must not be null");
        Objects.requireNonNull(responseType, "responseType must not be null");

        URI uri = parseUri(url);
        validator.validate(uri);

        return restTemplate.postForObject(Objects.requireNonNull(uri), body, responseType);
    }

    /**
     * Parses and validates URI format.
     *
     * Contract:
     * - Returns a valid URI
     * - Throws IllegalArgumentException if the format is invalid
     *
     * NOTE:
     * URI.create never returns null.
     */
    private URI parseUri(String url) {
        try {
            return URI.create(url);
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(
                    "Invalid URL format for outbound HTTP call",
                    ex);
        }
    }
}
