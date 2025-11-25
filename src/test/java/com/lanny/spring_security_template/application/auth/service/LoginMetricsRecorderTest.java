package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link LoginMetricsRecorder}.
 * Verifies that success/failure metrics are delegated correctly.
 */
class LoginMetricsRecorderTest {

    @Test
    @DisplayName(" should record login success and delegate to AuthMetricsService")
    void testShouldRecordLoginSuccess() {
        // Arrange
        AuthMetricsService metrics = mock(AuthMetricsService.class);
        LoginMetricsRecorder recorder = new LoginMetricsRecorder(metrics);

        // Act
        recorder.recordSuccess();

        // Assert
        verify(metrics).recordLoginSuccess();
        verify(metrics, never()).recordLoginFailure();
        verifyNoMoreInteractions(metrics);
    }

    @Test
    @DisplayName(" should record login failure and not call success")
    void testShouldRecordLoginFailure() {
        // Arrange
        AuthMetricsService metrics = mock(AuthMetricsService.class);
        LoginMetricsRecorder recorder = new LoginMetricsRecorder(metrics);

        // Act
        recorder.recordFailure();

        // Assert
        verify(metrics).recordLoginFailure();
        verify(metrics, never()).recordLoginSuccess();
        verifyNoMoreInteractions(metrics);
    }
}

