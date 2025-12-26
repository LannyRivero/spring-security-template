package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.testsupport.time.MutableClockProvider;
import com.lanny.spring_security_template.infrastructure.security.filter.LoginRateLimitingFilter;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import static org.mockito.Mockito.*;

class LoginRateLimitingFilterTimeTest {

    @Test
    @DisplayName("Should block login attempts after max allowed attempts")
    void shouldBlockAfterTooManyAttempts() throws Exception {

        // Arrange
        MutableClockProvider clock = new MutableClockProvider(
                java.time.Instant.parse("2030-01-01T00:00:00Z")
        );

        LoginRateLimitingFilter filter = new LoginRateLimitingFilter(clock);

        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(req.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(req.getRemoteAddr()).thenReturn("127.0.0.1");

        // Act — 6 attempts
        for (int i = 0; i < 6; i++) {
            filter.doFilter(req, res, chain);
        }

        // Assert
        verify(res).sendError(eq(429), anyString());
    }

    @Test
    @DisplayName("Should unlock after rate limit window passes")
    void shouldUnlockAfterWindowPasses() throws Exception {

        // Arrange
        MutableClockProvider clock = new MutableClockProvider(
                java.time.Instant.parse("2030-01-01T00:00:00Z")
        );
        LoginRateLimitingFilter filter = new LoginRateLimitingFilter(clock, 5, 60);

        HttpServletRequest req = mock(HttpServletRequest.class);
        HttpServletResponse res = mock(HttpServletResponse.class);
        FilterChain chain = mock(FilterChain.class);

        when(req.getRequestURI()).thenReturn("/api/v1/auth/login");
        when(req.getRemoteAddr()).thenReturn("127.0.0.1");

        // 5 blocked attempts
        for (int i = 0; i < 5; i++) {
            filter.doFilter(req, res, chain);
        }

        // Advance time so rate limit resets
        clock.advanceSeconds(61);

        // Act — new attempt should succeed
        filter.doFilter(req, res, chain);

        // Assert
        verify(chain, atLeastOnce()).doFilter(req, res);
    }
}

