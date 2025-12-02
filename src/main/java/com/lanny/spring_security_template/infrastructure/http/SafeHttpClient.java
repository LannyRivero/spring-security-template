package com.lanny.spring_security_template.infrastructure.http;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Objects;

@Component
public class SafeHttpClient {

    private final RestTemplate restTemplate;
    private final UrlSecurityValidator validator;

    public SafeHttpClient(RestTemplate restTemplate, UrlSecurityValidator validator) {
        this.restTemplate = restTemplate;
        this.validator = validator;
    }

    public <T> T get(String url, Class<T> type) {
        URI uri = Objects.requireNonNull(URI.create(url), "URI cannot be null");
        Objects.requireNonNull(type, "Type cannot be null");
        validator.validate(uri);
        return restTemplate.getForObject(uri, type);
    }

    public <T> T post(String url, Object body, Class<T> type) {
        URI uri = Objects.requireNonNull(URI.create(url), "URI cannot be null");
        Objects.requireNonNull(type, "Type cannot be null");
        validator.validate(uri);
        return restTemplate.postForObject(uri, body, type);
    }
}
