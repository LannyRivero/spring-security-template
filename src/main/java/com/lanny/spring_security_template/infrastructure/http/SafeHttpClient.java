package com.lanny.spring_security_template.infrastructure.http;

import com.lanny.spring_security_template.infrastructure.security.ssrf.UrlSecurityValidator;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class SafeHttpClient {

    private final RestTemplate restTemplate;
    private final UrlSecurityValidator urlValidator;

    public SafeHttpClient() {
        this.restTemplate = new RestTemplate();
        this.urlValidator = new UrlSecurityValidator();
    }

    public <T> ResponseEntity<T> get(String url, Class<T> responseType) {
        if (url == null) {
            throw new IllegalArgumentException("URL cannot be null");
        }
        if (responseType == null) {
            throw new IllegalArgumentException("Response type cannot be null");
        }
        urlValidator.validateOutboundUrl(url);
        return restTemplate.getForEntity(url, responseType);
    }

    // podrías añadir post, put, etc.
}
