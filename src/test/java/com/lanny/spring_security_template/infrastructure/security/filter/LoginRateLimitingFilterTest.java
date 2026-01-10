package com.lanny.spring_security_template.infrastructure.security.filter;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.io.PrintWriter;
import java.io.StringWriter;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
import com.lanny.spring_security_template.infrastructure.config.RateLimitingProperties;
import com.lanny.spring_security_template.infrastructure.security.handler.ApiError;
import com.lanny.spring_security_template.infrastructure.security.handler.ApiErrorFactory;
import com.lanny.spring_security_template.infrastructure.security.ratelimit.RateLimitKeyResolver;

import jakarta.servlet.FilterChain;

class LoginRateLimitingFilterTest {

    private RateLimitingProperties props;
    private RateLimitKeyResolver keyResolver;
    private ObjectMapper objectMapper;
    private LoginAttemptPolicy loginAttemptPolicy;
    private ApiErrorFactory errorFactory;

    private LoginRateLimitingFilter filter;

    @BeforeEach
    void setUp() {
        props = mock(RateLimitingProperties.class);
        keyResolver = mock(RateLimitKeyResolver.class);
        objectMapper = spy(new ObjectMapper()); // spy to verify writeValue if needed
        loginAttemptPolicy = mock(LoginAttemptPolicy.class);
        errorFactory = mock(ApiErrorFactory.class);

        filter = new LoginRateLimitingFilter(
                props, keyResolver, objectMapper, loginAttemptPolicy, errorFactory);
    }

    @Test
    @DisplayName("shouldNotFilter returns true when rate limiting disabled")
    void testShouldNotFilter_whenDisabled() {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        when(props.enabled()).thenReturn(false);

        boolean result = filter.shouldNotFilter(req);

        org.junit.jupiter.api.Assertions.assertTrue(result);
    }

    @Test
    @DisplayName("shouldNotFilter returns true when path differs")
    void testShouldNotFilter_whenPathDifferent() {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/other");
        when(props.enabled()).thenReturn(true);
        when(props.loginPath()).thenReturn("/api/v1/auth/login");

        boolean result = filter.shouldNotFilter(req);

        org.junit.jupiter.api.Assertions.assertTrue(result);
    }

    @Test
    @DisplayName("shouldNotFilter returns true when method differs")
    void testShouldNotFilter_whenMethodDifferent() {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", "/api/v1/auth/login");
        when(props.enabled()).thenReturn(true);
        when(props.loginPath()).thenReturn("/api/v1/auth/login");

        boolean result = filter.shouldNotFilter(req);

        org.junit.jupiter.api.Assertions.assertTrue(result);
    }

    @Test
    @DisplayName("when allowed -> continues filter chain")
    void testShouldDoFilterInternal_whenAllowed_continuesChain() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        when(props.enabled()).thenReturn(true);
        when(props.loginPath()).thenReturn("/api/v1/auth/login");

        when(keyResolver.resolveKey(req)).thenReturn("k");
        when(loginAttemptPolicy.registerAttempt("k")).thenReturn(LoginAttemptResult.allowAccess());

        filter.doFilter(req, res, chain);

        verify(chain, times(1)).doFilter(req, res);
        org.junit.jupiter.api.Assertions.assertNotEquals(HttpStatus.TOO_MANY_REQUESTS.value(), res.getStatus());
    }

    @Test
    @DisplayName("when blocked -> returns 429 and sets Retry-After header")
    void testDoFilterInternal_whenBlocked_returns429() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        when(props.enabled()).thenReturn(true);
        when(props.loginPath()).thenReturn("/api/v1/auth/login");
        when(props.strategy()).thenReturn("IP_USER");

        when(keyResolver.resolveKey(req)).thenReturn("k");
        when(loginAttemptPolicy.registerAttempt("k")).thenReturn(LoginAttemptResult.blocked(120));

        when(errorFactory.create(eq(429), anyString(), eq(req))).thenReturn(
                mock(ApiError.class)
        );

        // Ensure response writer exists (MockHttpServletResponse does)
        filter.doFilter(req, res, chain);

        verify(chain, never()).doFilter(req, res);
        org.junit.jupiter.api.Assertions.assertEquals(429, res.getStatus());
        org.junit.jupiter.api.Assertions.assertEquals("120", res.getHeader("Retry-After"));
        org.junit.jupiter.api.Assertions.assertNotNull(res.getContentType());
        org.junit.jupiter.api.Assertions.assertTrue(res.getContentType() != null && res.getContentType().startsWith("application/json"));
        org.junit.jupiter.api.Assertions.assertTrue(res.getContentAsString().contains("Too many login attempts"));
    }

    @Test
    @DisplayName("when blocked with retryAfter=0 -> returns 429 without Retry-After header")
    void testShouldDoFilterInternal_whenBlockedNoRetryAfter_returns429WithoutHeader() throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("POST", "/api/v1/auth/login");
        MockHttpServletResponse res = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);

        when(props.enabled()).thenReturn(true);
        when(props.loginPath()).thenReturn("/api/v1/auth/login");
        when(props.strategy()).thenReturn("IP");

        when(keyResolver.resolveKey(req)).thenReturn("k");
        when(loginAttemptPolicy.registerAttempt("k")).thenReturn(LoginAttemptResult.blocked(0));

        when(errorFactory.create(eq(429), anyString(), eq(req))).thenReturn(
                mock(ApiError.class)
        );

        filter.doFilter(req, res, chain);

        verify(chain, never()).doFilter(req, res);
        org.junit.jupiter.api.Assertions.assertEquals(429, res.getStatus());
        org.junit.jupiter.api.Assertions.assertNull(res.getHeader("Retry-After"));
    }
}
