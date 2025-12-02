package com.lanny.spring_security_template.infrastructure.http;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.util.Objects;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

class SafeHttpClientTest {

    private final RestTemplate restTemplate = mock(RestTemplate.class);
    private final UrlSecurityValidator validator = mock(UrlSecurityValidator.class);

    private final SafeHttpClient client = new SafeHttpClient(restTemplate, validator);

    // --------------------------------------------------------------
    // GET SUCCESS
    // --------------------------------------------------------------
    @Test
    @DisplayName("testShouldPerformGetRequestSuccessfully")
    void testShouldPerformGetRequestSuccessfully() {
        String url = "https://api.example.com/data";

        URI uri = Objects.requireNonNull(URI.create(url));


        when(restTemplate.getForObject(uri, String.class)).thenReturn("OK");

        client.get(url, String.class);

        verify(validator).validate(uri);
        verify(restTemplate).getForObject(uri, String.class);
    }

    // --------------------------------------------------------------
    // POST SUCCESS
    // --------------------------------------------------------------
    @Test
    @DisplayName("testShouldPerformPostRequestSuccessfully")
    void testShouldPerformPostRequestSuccessfully() {
        String url = "https://api.example.com/new";

        URI uri = Objects.requireNonNull(URI.create(url));
        Object body = new Object();

        when(restTemplate.postForObject(uri, body, String.class)).thenReturn("CREATED");

        client.post(url, body, String.class);

        verify(validator).validate(uri);
        verify(restTemplate).postForObject(uri, body, String.class);
    }

    // --------------------------------------------------------------
    // VALIDATOR BLOCKED URL
    // --------------------------------------------------------------
    @Test
    @DisplayName("testShouldFailWhenUrlIsBlockedByValidator")
    void testShouldFailWhenUrlIsBlockedByValidator() {
        String url = "http://localhost/admin";

        URI uri = Objects.requireNonNull(URI.create(url));

        doThrow(new IllegalArgumentException("Blocked host"))
                .when(validator)
                .validate(uri);

        assertThatThrownBy(() -> client.get(url, String.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Blocked host");

        verify(validator).validate(uri);
        verifyNoInteractions(restTemplate);
    }

    // --------------------------------------------------------------
    // INVALID SCHEME
    // --------------------------------------------------------------
    @Test
    @DisplayName("testShouldFailWhenUrlHasInvalidScheme")
    void testShouldFailWhenUrlHasInvalidScheme() {
        String url = "ftp://evil.com";

        URI uri = Objects.requireNonNull(URI.create(url));

        doThrow(new IllegalArgumentException("Invalid URL scheme"))
                .when(validator).validate(uri);

        assertThatThrownBy(() -> client.get(url, String.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid URL scheme");

        verify(validator).validate(uri);
        verifyNoInteractions(restTemplate);
    }

    // --------------------------------------------------------------
    // RESTTEMPLATE THROWS RUNTIME EXCEPTION
    // --------------------------------------------------------------
    @Test
    @DisplayName("testShouldPropagateRestTemplateException")
    void testShouldPropagateRestTemplateException() {
        String url = "https://api.example.com/fail";

        URI uri = Objects.requireNonNull(URI.create(url));

        when(restTemplate.getForObject(uri, String.class))
                .thenThrow(new RuntimeException("Connection failed"));

        assertThatThrownBy(() -> client.get(url, String.class))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Connection failed");

        verify(validator).validate(uri);
        verify(restTemplate).getForObject(uri, String.class);
    }

    // --------------------------------------------------------------
    // URL WITHOUT HOST
    // --------------------------------------------------------------
    @Test
    @DisplayName("testShouldFailWhenUrlHasNoHost")
    void testShouldFailWhenUrlHasNoHost() {
        String url = "http:///nohost";

        URI uri = Objects.requireNonNull(URI.create(url));

        doThrow(new IllegalArgumentException("URL host cannot be null"))
                .when(validator).validate(uri);

        assertThatThrownBy(() -> client.get(url, String.class))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("URL host cannot be null");

        verify(validator).validate(uri);
        verifyNoInteractions(restTemplate);
    }
}
