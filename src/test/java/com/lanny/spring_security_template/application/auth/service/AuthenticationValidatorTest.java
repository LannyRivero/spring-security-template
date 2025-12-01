package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;

@ExtendWith(MockitoExtension.class)
class AuthenticationValidatorTest {

    private static final String USERNAME = "lanny";
    private static final String PASSWORD = "1234";

    @Mock private UserAccountGateway userAccountGateway;
    @Mock private PasswordHasher passwordHasher;
    @Mock private User mockUser;

    @InjectMocks
    private AuthenticationValidator validator;

    private PasswordHash hash;

    @BeforeEach
    void setUp() {
        reset(userAccountGateway, passwordHasher, mockUser);
        hash = PasswordHash.of("$mockedHashValue1234567890");
    }

    // ------------------------------------------------------------
    @Test
    @DisplayName("validate() → should return user when credentials are correct")
    void testShouldValidateUserSuccessfully() {

        LoginCommand cmd = new LoginCommand(USERNAME, PASSWORD);

        when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                .thenReturn(Optional.of(mockUser));

        when(mockUser.passwordHash()).thenReturn(hash);

        doNothing().when(mockUser).ensureCanAuthenticate();

        when(passwordHasher.matches(PASSWORD, hash.value())).thenReturn(true);

        User result = validator.validate(cmd);

        assertThat(result).isEqualTo(mockUser);

        verify(mockUser).ensureCanAuthenticate();
        verify(passwordHasher).matches(PASSWORD, hash.value()); // FIX
    }

    // ------------------------------------------------------------
    @Test
    @DisplayName("validate() → should throw InvalidCredentialsException when user does not exist")
    void testShouldThrowWhenUserNotFound() {

        LoginCommand cmd = new LoginCommand(USERNAME, PASSWORD);

        when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                .thenReturn(Optional.empty());

        assertThatThrownBy(() -> validator.validate(cmd))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid username or password");

        verifyNoInteractions(mockUser);
    }

    // ------------------------------------------------------------
    @Test
    @DisplayName("validate() → should throw InvalidCredentialsException when password does not match")
    void testShouldThrowWhenInvalidPassword() {

        LoginCommand cmd = new LoginCommand(USERNAME, PASSWORD);

        when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                .thenReturn(Optional.of(mockUser));

        when(mockUser.passwordHash()).thenReturn(hash);

        doNothing().when(mockUser).ensureCanAuthenticate();

        when(passwordHasher.matches(PASSWORD, hash.value()))
                .thenReturn(false);

        assertThatThrownBy(() -> validator.validate(cmd))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessage("Invalid username or password");

        verify(mockUser).ensureCanAuthenticate();
        verify(passwordHasher).matches(PASSWORD, hash.value()); // FIX
    }

    // ------------------------------------------------------------
    @Test
    @DisplayName("validate() → should propagate domain exceptions such as locked user")
    void testShouldPropagateDomainExceptions() {

        LoginCommand cmd = new LoginCommand(USERNAME, PASSWORD);

        when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                .thenReturn(Optional.of(mockUser));

        doThrow(new IllegalStateException("User locked"))
                .when(mockUser).ensureCanAuthenticate();

        assertThatThrownBy(() -> validator.validate(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("User locked");

        verify(mockUser).ensureCanAuthenticate();
        verify(mockUser, never()).passwordHash();
        verify(passwordHasher, never()).matches(any(), any());
    }
}

