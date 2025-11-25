package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceImpl;

@ExtendWith(MockitoExtension.class)
class DevRegisterServiceTest {

    @Mock
    private UserAccountGateway userAccountGateway;
    @Mock
    private PasswordHasher passwordHasher;
    @Mock
    private AuthMetricsServiceImpl metrics;

    @InjectMocks
    private DevRegisterService devRegisterService;

    private RegisterCommand command;

    private static final String VALID_HASH = "$2a$10$ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghiJKLMNOPQRSTUV1234567890";

    @BeforeEach
    void setUp() {
        command = new RegisterCommand(
                "lanny",
                "lanny@example.com",
                "rawPass123",
                List.of("ADMIN"),
                List.of("profile:read"));
    }

    @Test
    @DisplayName(" should hash password, create new User, save it and record metric")
    void testShouldCreateAndSaveUserWhenCommandValid() {
        when(passwordHasher.hash("rawPass123")).thenReturn(VALID_HASH);

        devRegisterService.register(command);

        ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
        verify(userAccountGateway).save(userCaptor.capture());
        verify(passwordHasher).hash("rawPass123");
        verify(metrics).recordUserRegistration();

        User savedUser = userCaptor.getValue();
        assertThat(savedUser.username().value()).isEqualTo("lanny");
        assertThat(savedUser.email().value()).isEqualTo("lanny@example.com");
        assertThat(savedUser.passwordHash().value()).isEqualTo(VALID_HASH);
    }

    @Test
    @DisplayName(" should propagate exception when PasswordHasher fails")
    void testShouldPropagateExceptionWhenPasswordHasherFails() {
        when(passwordHasher.hash(any())).thenThrow(new IllegalStateException("Hashing failure"));

        assertThatThrownBy(() -> devRegisterService.register(command))
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("Hashing failure");

        verify(passwordHasher).hash("rawPass123");
        verifyNoInteractions(userAccountGateway, metrics);
    }

    @Test
    @DisplayName(" should propagate exception when UserAccountGateway fails to save user")
    void testShouldPropagateExceptionWhenUserAccountGatewayFails() {
        when(passwordHasher.hash(any())).thenReturn(VALID_HASH);
        doThrow(new RuntimeException("DB failure")).when(userAccountGateway).save(any(User.class));

        assertThatThrownBy(() -> devRegisterService.register(command))
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("DB failure");

        verify(passwordHasher).hash("rawPass123");
        verify(userAccountGateway).save(any(User.class));
        verifyNoInteractions(metrics);
    }

    @Test
    @DisplayName(" should handle empty roles and scopes gracefully")
    void testShouldCreateUserWhenRolesAndScopesEmpty() {
        RegisterCommand cmd = new RegisterCommand(
                "simpleUser",
                "user@mail.com",
                "123456",
                List.of(),
                List.of());
        when(passwordHasher.hash("123456")).thenReturn(VALID_HASH);

        devRegisterService.register(cmd);

        verify(passwordHasher).hash("123456");
        verify(userAccountGateway).save(any(User.class));
        verify(metrics).recordUserRegistration();
    }

    @Test
    @DisplayName(" should build value objects correctly using static factories")
    void testShouldUseValueObjectFactories() {
        when(passwordHasher.hash("rawPass123")).thenReturn(VALID_HASH);

        devRegisterService.register(command);

        verify(userAccountGateway).save(argThat(user -> user.username().equals(Username.of("lanny"))
                && user.email().equals(EmailAddress.of("lanny@example.com"))
                && user.passwordHash().equals(PasswordHash.of(VALID_HASH))));
    }
}
