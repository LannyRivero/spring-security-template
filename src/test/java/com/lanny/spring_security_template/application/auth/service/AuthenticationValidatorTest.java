package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;

/**
 * Unit tests for {@link AuthenticationValidator}.
 */
@ExtendWith(MockitoExtension.class)
class AuthenticationValidatorTest {

    @Mock
    private UserAccountGateway userAccountGateway;
    @Mock
    private PasswordHasher passwordHasher;
    @Mock
    private User mockUser;

    @InjectMocks
    private AuthenticationValidator validator;

    private static final String USERNAME = "lanny";
    private static final String PASSWORD = "1234";

    @BeforeEach
    void setUp() {
        reset(userAccountGateway, passwordHasher, mockUser);
    }

    @Test
    @DisplayName(" should validate user successfully when credentials are correct")
    void testShouldValidateUserSuccessfully() {
        // Arrange
        LoginCommand cmd = new LoginCommand(USERNAME, PASSWORD);
        when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                .thenReturn(Optional.of(mockUser));

        doNothing().when(mockUser).ensureCanAuthenticate();
        doNothing().when(mockUser).verifyPassword(eq(PASSWORD), eq(passwordHasher));

        // Act
        User result = validator.validate(cmd);

        // Assert
        assertThat(result).isEqualTo(mockUser);
        verify(userAccountGateway).findByUsernameOrEmail(USERNAME);
        verify(mockUser).ensureCanAuthenticate();
        verify(mockUser).verifyPassword(PASSWORD, passwordHasher);
    }

    @Test
    @DisplayName(" should throw UsernameNotFoundException when user not found")
    void testShouldThrowWhenUserNotFound() {
        LoginCommand cmd = new LoginCommand(USERNAME, PASSWORD);
        when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> validator.validate(cmd))
                .isInstanceOf(UsernameNotFoundException.class)
                .hasMessage(USERNAME);

        verify(userAccountGateway).findByUsernameOrEmail(USERNAME);
        verifyNoInteractions(mockUser);
    }

    @Test
    @DisplayName(" should throw InvalidCredentialsException when password is incorrect")
    void testShouldThrowWhenInvalidPassword() {
        LoginCommand cmd = new LoginCommand(USERNAME, PASSWORD);
        when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                .thenReturn(Optional.of(mockUser));

        doNothing().when(mockUser).ensureCanAuthenticate();
        doThrow(new InvalidCredentialsException("Bad password"))
                .when(mockUser).verifyPassword(eq(PASSWORD), eq(passwordHasher));

        assertThatThrownBy(() -> validator.validate(cmd))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid username or password");

        verify(mockUser).ensureCanAuthenticate();
        verify(mockUser).verifyPassword(PASSWORD, passwordHasher);
    }

    @Test
    @DisplayName(" should propagate unexpected exceptions (e.g., locked user)")
    void testShouldPropagateUnexpectedExceptions() {
        LoginCommand cmd = new LoginCommand(USERNAME, PASSWORD);
        when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                .thenReturn(Optional.of(mockUser));

        doThrow(new IllegalStateException("User locked"))
                .when(mockUser).ensureCanAuthenticate();

        assertThatThrownBy(() -> validator.validate(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("User locked");

        verify(mockUser).ensureCanAuthenticate();
        verify(mockUser, never()).verifyPassword(any(), any());
    }
}
