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
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
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
    @DisplayName("Should login successfully when credentials are valid")
    void shouldLoginSuccessfully() {

        when(validator.validate(cmd)).thenReturn(mockUser);
        when(mockUser.username()).thenReturn(Username.of(USERNAME));
        when(tokenCreator.create(USERNAME)).thenReturn(jwtResult);

        JwtResult result = loginService.login(cmd);

        assertThat(result).isEqualTo(jwtResult);

        verify(validator).validate(cmd);
        verify(tokenCreator).create(USERNAME);
        verify(loginAttemptPolicy).resetAttempts(USERNAME);
        verify(metrics).recordSuccess(USERNAME);

        verify(loginAttemptPolicy, never()).registerAttempt(any());
        verify(metrics, never()).recordFailure(any(), any());
    }

    // ==============================================================================
    @Test
    @DisplayName("Should throw UserLockedException when policy blocks after failed attempt")
    void shouldThrowUserLockedExceptionWhenBlocked() {

        when(validator.validate(cmd))
                .thenThrow(new InvalidCredentialsException("bad creds"));

        when(loginAttemptPolicy.registerAttempt(USERNAME))
                .thenReturn(new LoginAttemptResult(true, 60));

        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(UserLockedException.class);

        verify(loginAttemptPolicy).registerAttempt(USERNAME);
        verify(metrics).recordFailure(eq(USERNAME), contains("User locked"));
        verify(tokenCreator, never()).create(any());
    }

    // ==============================================================================
    @Test
    @DisplayName("Should record failed attempt and throw InvalidCredentialsException when not blocked")
    void shouldRecordFailedAttemptWhenInvalidCredentials() {

        when(validator.validate(cmd))
                .thenThrow(new InvalidCredentialsException("bad creds"));

        when(loginAttemptPolicy.registerAttempt(USERNAME))
                .thenReturn(new LoginAttemptResult(false, 0));

        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(InvalidCredentialsException.class);

        verify(loginAttemptPolicy).registerAttempt(USERNAME);
        verify(metrics).recordFailure(eq(USERNAME), contains("Invalid"));
        verify(metrics, never()).recordSuccess(any());
        verify(tokenCreator, never()).create(any());
    }

    // ==============================================================================
    @Test
    @DisplayName("Should record failed attempt and throw UserNotFoundException when not blocked")
    void shouldRecordFailedAttemptWhenUserNotFound() {

        when(validator.validate(cmd))
                .thenThrow(new UserNotFoundException(USERNAME));

        when(loginAttemptPolicy.registerAttempt(USERNAME))
                .thenReturn(new LoginAttemptResult(false, 0));

        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(UserNotFoundException.class);

        verify(loginAttemptPolicy).registerAttempt(USERNAME);
        verify(metrics).recordFailure(eq(USERNAME), contains("Invalid"));
        verify(metrics, never()).recordSuccess(any());
        verify(tokenCreator, never()).create(any());
    }

    // ==============================================================================
    @Test
    @DisplayName("Should propagate unexpected exception without recording attempts or metrics")
    void shouldPropagateUnexpectedException() {

        when(validator.validate(cmd))
                .thenThrow(new IllegalStateException("DB issue"));

        assertThatThrownBy(() -> loginService.login(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("DB issue");

        verify(loginAttemptPolicy, never()).registerAttempt(any());
        verify(loginAttemptPolicy, never()).resetAttempts(any());
        verify(metrics, never()).recordSuccess(any());
        verify(metrics, never()).recordFailure(any(), any());
        verifyNoInteractions(tokenCreator);
    }
}
