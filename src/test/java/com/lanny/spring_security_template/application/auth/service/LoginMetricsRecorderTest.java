package com.lanny.spring_security_template.application.auth.service;

import static org.mockito.Mockito.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;

/**
 * Unit tests for {@link LoginMetricsRecorder}.
 * Verifies that contextual metrics are delegated correctly.
 */
class LoginMetricsRecorderTest {

    @Test
    @DisplayName("should record login success and delegate to AuthMetricsService")
    void testShouldRecordLoginSuccess() {
        // Arrange
        AuthMetricsService metrics = mock(AuthMetricsService.class);
        LoginMetricsRecorder recorder = new LoginMetricsRecorder(metrics);
        String username = "lanny";

        // Act
        recorder.recordSuccess(username);

        // Assert
        verify(metrics).recordLoginSuccess();
        verify(metrics, never()).recordLoginFailure();
        verifyNoMoreInteractions(metrics);
    }

    @Test
    @DisplayName("should record login failure and delegate correctly")
    void testShouldRecordLoginFailure() {
        // Arrange
        AuthMetricsService metrics = mock(AuthMetricsService.class);
        LoginMetricsRecorder recorder = new LoginMetricsRecorder(metrics);
        String username = "lanny";
        String reason = "invalid_password";

        // Act
        recorder.recordFailure(username, reason);

        // Assert
        verify(metrics).recordLoginFailure();
        verify(metrics, never()).recordLoginSuccess();
        verifyNoMoreInteractions(metrics);
    }
}
