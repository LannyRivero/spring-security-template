package com.lanny.spring_security_template.infrastructure.http;

import com.lanny.spring_security_template.infrastructure.security.ssrf.UrlSecurityValidator;
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
 * All destination security rules are delegated to UrlSecurityValidator.
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
        Objects.requireNonNull(uri, "parsed URI must not be null");
        validator.validate(uri);

        return restTemplate.getForObject(uri, responseType);
    }

    public <T> T post(String url, Object body, Class<T> responseType) {

        Objects.requireNonNull(url, "url must not be null");
        Objects.requireNonNull(responseType, "responseType must not be null");

        URI uri = parseUri(url);
        Objects.requireNonNull(uri, "parsed URI must not be null");
        validator.validate(uri);

        return restTemplate.postForObject(uri, body, responseType);
    }

    /**
     * Parses and normalizes a URL into a URI.
     *
     * @throws IllegalArgumentException if the URL format is invalid
     */
    private URI parseUri(String url) {
        try {
            return URI.create(url).normalize();
        } catch (IllegalArgumentException ex) {
            throw new IllegalArgumentException(
                    "Invalid URL format for outbound HTTP call",
                    ex);
        }
    }
}
