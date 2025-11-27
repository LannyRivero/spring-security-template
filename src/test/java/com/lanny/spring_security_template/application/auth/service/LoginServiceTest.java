package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
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
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.valueobject.Username;

/**
 * Unit tests for {@link LoginService}.
 *
 * <p>
 * Verifies orchestration between:
 * </p>
 * <ul>
 * <li>{@link AuthenticationValidator}</li>
 * <li>{@link TokenSessionCreator}</li>
 * <li>{@link LoginMetricsRecorder}</li>
 * <li>{@link LoginAttemptPolicy}</li>
 * </ul>
 *
 * <p>
 * Ensures correct behavior for:
 * <ul>
 * <li>Successful authentication</li>
 * <li>Invalid credentials</li>
 * <li>User not found</li>
 * <li>Temporary user lockout (brute-force protection)</li>
 * <li>Unexpected exceptions</li>
 * </ul>
 * </p>
 */
@ExtendWith(MockitoExtension.class)
class LoginServiceTest {

    @Mock
    private AuthenticationValidator validator;
    @Mock
    private TokenSessionCreator tokenCreator;
    @Mock
    private LoginMetricsRecorder metrics;
    @Mock
    private LoginAttemptPolicy loginAttemptPolicy;

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
    @DisplayName(" Should login successfully, reset attempts and record success metric")
    void testShouldLoginSuccessfully() {
        // Arrange
        User mockUser = mock(User.class);
        when(mockUser.username()).thenReturn(Username.of("lanny"));
        when(loginAttemptPolicy.isUserLocked("lanny")).thenReturn(false);
        when(validator.validate(cmd)).thenReturn(mockUser);
        when(tokenCreator.create("lanny")).thenReturn(jwtResult);

        // Act
        JwtResult result = loginService.login(cmd);

        // Assert
        assertThat(result).isEqualTo(jwtResult);
        verify(loginAttemptPolicy).isUserLocked("lanny");
        verify(validator).validate(cmd);
        verify(tokenCreator).create("lanny");
        verify(loginAttemptPolicy).resetAttempts("lanny");
        verify(metrics).recordSuccess();
        verify(metrics, never()).recordFailure();
    }

    @Test
    @DisplayName(" Should throw UserLockedException if user is temporarily locked")
    void testShouldThrowWhenUserLocked() {
        // Arrange
        when(loginAttemptPolicy.isUserLocked("lanny")).thenReturn(true);

        // Act & Assert
        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(UserLockedException.class)
                .hasMessageContaining("lanny");

        verify(loginAttemptPolicy).isUserLocked("lanny");
        verify(metrics).recordFailure();
        verifyNoInteractions(validator, tokenCreator);
    }

    @Test
    @DisplayName(" Should record failure and increment attempts when credentials are invalid")
    void testShouldRecordFailureOnInvalidCredentials() {
        // Arrange
        when(loginAttemptPolicy.isUserLocked("lanny")).thenReturn(false);
        when(validator.validate(cmd)).thenThrow(new InvalidCredentialsException("Invalid username or password"));

        // Act & Assert
        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid username or password");

        verify(loginAttemptPolicy).isUserLocked("lanny");
        verify(validator).validate(cmd);
        verify(loginAttemptPolicy).recordFailedAttempt("lanny");
        verify(metrics).recordFailure();
        verifyNoInteractions(tokenCreator);
    }

    @Test
    @DisplayName(" Should record failure and increment attempts when user not found")
    void testShouldRecordFailureOnUserNotFound() {
        // Arrange
        when(loginAttemptPolicy.isUserLocked("lanny")).thenReturn(false);
        when(validator.validate(cmd)).thenThrow(new UsernameNotFoundException("lanny"));

        // Act & Assert
        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage("lanny");

        verify(loginAttemptPolicy).isUserLocked("lanny");
        verify(validator).validate(cmd);
        verify(loginAttemptPolicy).recordFailedAttempt("lanny");
        verify(metrics).recordFailure();
        verify(metrics, never()).recordSuccess();
        verifyNoInteractions(tokenCreator);
    }

    @Test
    @DisplayName(" Should propagate unexpected exceptions without metrics or lockout updates")
    void testShouldPropagateUnexpectedException() {
        // Arrange
        when(loginAttemptPolicy.isUserLocked("lanny")).thenReturn(false);
        when(validator.validate(cmd)).thenThrow(new IllegalStateException("DB connection lost"));

        // Act & Assert
        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("DB connection lost");

        verify(loginAttemptPolicy).isUserLocked("lanny");
        verify(validator).validate(cmd);
        verify(metrics, never()).recordSuccess();
        verify(metrics, never()).recordFailure();
        verify(loginAttemptPolicy, never()).recordFailedAttempt(anyString());
        verifyNoInteractions(tokenCreator);
    }
}
