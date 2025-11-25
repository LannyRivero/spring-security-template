package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.time.Instant;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.valueobject.Username;

/**
 * Unit tests for {@link LoginService}.
 * Verifies orchestration of validator, token creation and metrics recording.
 */
@ExtendWith(MockitoExtension.class)
class LoginServiceTest {

    @Mock
    private AuthenticationValidator validator;
    @Mock
    private TokenSessionCreator tokenCreator;
    @Mock
    private LoginMetricsRecorder metrics;

    @InjectMocks
    private LoginService loginService;

    private LoginCommand cmd;
    private JwtResult jwtResult;

    @BeforeEach
    void setUp() {
        cmd = new LoginCommand("lanny", "1234");
        jwtResult = new JwtResult("access-token", "refresh-token", Instant.now());

    }

    @Test
    @DisplayName(" should login successfully and record success metric")
    void tesShouldLoginSuccessfully() {
        // Arrange
        User mockUser = mock(User.class);
        when(mockUser.username()).thenReturn(Username.of("lanny"));
        when(validator.validate(cmd)).thenReturn(mockUser);
        when(tokenCreator.create("lanny")).thenReturn(jwtResult);

        // Act
        JwtResult result = loginService.login(cmd);

        // Assert
        assertThat(result).isEqualTo(jwtResult);
        verify(validator).validate(cmd);
        verify(tokenCreator).create("lanny");
        verify(metrics).recordSuccess();
        verify(metrics, never()).recordFailure();
    }

    @Test
    @DisplayName(" should record failure metric when credentials are invalid")
    void tesShouldRecordFailureWhenInvalidCredentials() {
        // Arrange
        when(validator.validate(cmd)).thenThrow(new InvalidCredentialsException("Invalid username or password"));

        // Act & Assert
        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid username or password");

        verify(validator).validate(cmd);
        verify(metrics).recordFailure();
        verify(metrics, never()).recordSuccess();
        verifyNoInteractions(tokenCreator);
    }

    @Test
    @DisplayName(" should record failure metric when user not found")
    void tesShouldRecordFailureWhenUserNotFound() {
        // Arrange
        when(validator.validate(cmd)).thenThrow(new UsernameNotFoundException("lanny"));

        // Act & Assert
        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage("lanny");

        verify(validator).validate(cmd);
        verify(metrics).recordFailure();
        verify(metrics, never()).recordSuccess();
        verifyNoInteractions(tokenCreator);
    }

    @Test
    @DisplayName(" should propagate unexpected runtime exceptions without recording metrics")
    void tesShouldPropagateUnexpectedException() {
        // Arrange
        when(validator.validate(cmd)).thenThrow(new IllegalStateException("DB connection lost"));

        // Act & Assert
        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("DB connection lost");

        // Verificamos que no se registran métricas para errores no previstos
        verify(metrics, never()).recordSuccess();
        verify(metrics, never()).recordFailure();
        verifyNoInteractions(tokenCreator);
    }
}
