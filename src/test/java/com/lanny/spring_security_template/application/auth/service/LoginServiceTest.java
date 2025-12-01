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

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.exception.UserNotFoundException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.valueobject.Username;

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

    @Mock
    private User mockUser;

    @InjectMocks
    private LoginService loginService;

    private static final String USERNAME = "lanny";
    private static final String PASSWORD = "1234";

    private LoginCommand cmd;
    private JwtResult jwtResult;

    @BeforeEach
    void setUp() {
        cmd = new LoginCommand(USERNAME, PASSWORD);
        jwtResult = new JwtResult("ACCESS", "REFRESH", Instant.now().plusSeconds(500));
    }

    // ==============================================================================
    @Test
    @DisplayName("testShouldLoginSuccessfullyWhenCredentialsAreValid")
    void testShouldLoginSuccessfullyWhenCredentialsAreValid() {
        when(loginAttemptPolicy.isUserLocked(USERNAME)).thenReturn(false);
        when(validator.validate(cmd)).thenReturn(mockUser);
        when(mockUser.username()).thenReturn(Username.of(USERNAME));
        when(tokenCreator.create(USERNAME)).thenReturn(jwtResult);

        JwtResult result = loginService.login(cmd);

        assertThat(result).isEqualTo(jwtResult);

        verify(loginAttemptPolicy).isUserLocked(USERNAME);
        verify(validator).validate(cmd);
        verify(tokenCreator).create(USERNAME);
        verify(loginAttemptPolicy).resetAttempts(USERNAME);
        verify(metrics).recordSuccess(USERNAME);

        verify(metrics, never()).recordFailure(any(), any());
    }

    // ==============================================================================
    @Test
    @DisplayName("testShouldThrowUserLockedExceptionWhenUserIsLocked")
    void testShouldThrowUserLockedExceptionWhenUserIsLocked() {
        when(loginAttemptPolicy.isUserLocked(USERNAME)).thenReturn(true);

        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(UserLockedException.class);

        verify(metrics).recordFailure(eq(USERNAME), contains("User locked"));
        verifyNoInteractions(validator, tokenCreator);
    }

    // ==============================================================================
    @Test
    @DisplayName("testShouldRecordFailureAndThrowInvalidCredentialsException")
    void testShouldRecordFailureAndThrowInvalidCredentialsException() {
        when(loginAttemptPolicy.isUserLocked(USERNAME)).thenReturn(false);
        when(validator.validate(cmd))
                .thenThrow(new InvalidCredentialsException("bad creds"));

        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(loginAttemptPolicy).recordFailedAttempt(USERNAME);
        verify(metrics).recordFailure(eq(USERNAME), contains("bad"));
        verify(metrics, never()).recordSuccess(any());
        verifyNoInteractions(tokenCreator);
    }

    // ==============================================================================
    @Test
    @DisplayName("testShouldRecordFailureAndThrowUserNotFoundException")
    void testShouldRecordFailureAndThrowUserNotFoundException() {
        when(loginAttemptPolicy.isUserLocked(USERNAME)).thenReturn(false);
        when(validator.validate(cmd))
                .thenThrow(new UserNotFoundException(USERNAME));

        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(UserNotFoundException.class);

        verify(loginAttemptPolicy).recordFailedAttempt(USERNAME);
        verify(metrics).recordFailure(eq(USERNAME), contains(USERNAME));
        verify(metrics, never()).recordSuccess(any());
        verifyNoInteractions(tokenCreator);
    }

    // ==============================================================================
    @Test
    @DisplayName("testShouldPropagateUnexpectedExceptionWithoutRecordingMetrics")
    void testShouldPropagateUnexpectedExceptionWithoutRecordingMetrics() {
        when(loginAttemptPolicy.isUserLocked(USERNAME)).thenReturn(false);
        when(validator.validate(cmd))
                .thenThrow(new IllegalStateException("DB issue"));

        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("DB issue");

        verify(metrics, never()).recordSuccess(any());
        verify(metrics, never()).recordFailure(any(), any());
        verify(loginAttemptPolicy, never()).recordFailedAttempt(any());
        verifyNoInteractions(tokenCreator);
    }
}
