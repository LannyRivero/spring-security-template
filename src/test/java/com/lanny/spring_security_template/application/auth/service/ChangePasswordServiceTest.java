package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.UserId;
import com.lanny.spring_security_template.domain.valueobject.Username;

/**
 * Unit tests for {@link ChangePasswordService}.
 */
class ChangePasswordServiceTest {

    private UserAccountGateway userAccountGateway;
    private RefreshTokenStore refreshTokenStore;
    private PasswordHasher passwordHasher;
    private PasswordPolicy passwordPolicy;
    private AuthMetricsService metrics;
    private ClockProvider clockProvider;
    private AuditEventPublisher auditEventPublisher;

    private ChangePasswordService service;

    private static final String USERNAME = "lanny";
    private static final String CURRENT_PASSWORD = "OldPass1!";
    private static final String NEW_PASSWORD = "NewPass1!";
    private static final String VALID_HASH = "$2a$10$abcdefghijklmnopqrstuv1234567890abcdefghiJKLMNOpqrstuVWXYZ";

    private User user;

    @BeforeEach
    void setUp() {
        userAccountGateway = mock(UserAccountGateway.class);
        refreshTokenStore = mock(RefreshTokenStore.class);
        passwordHasher = mock(PasswordHasher.class);
        passwordPolicy = mock(PasswordPolicy.class);
        metrics = mock(AuthMetricsService.class);
        clockProvider = mock(ClockProvider.class);
        auditEventPublisher = mock(AuditEventPublisher.class);

        service = new ChangePasswordService(
                userAccountGateway,
                refreshTokenStore,
                passwordHasher,
                passwordPolicy,
                metrics,
                clockProvider,
                auditEventPublisher);

        user = User.rehydrate(
                UserId.newId(),
                Username.of(USERNAME),
                EmailAddress.of("user@example.com"),
                PasswordHash.of(VALID_HASH),
                UserStatus.ACTIVE,
                List.of("ROLE_USER"),
                List.of("read:profile"));

        when(clockProvider.now()).thenReturn(Instant.now());
    }

    @Test
    @DisplayName(" should change password successfully and invalidate sessions")
    void testShouldChangePasswordSuccessfully() {
        when(userAccountGateway.findByUsernameOrEmail(USERNAME)).thenReturn(Optional.of(user));
        when(passwordHasher.matches(CURRENT_PASSWORD, VALID_HASH)).thenReturn(true);
        when(passwordHasher.hash(NEW_PASSWORD)).thenReturn(VALID_HASH);

        service.changePassword(USERNAME, CURRENT_PASSWORD, NEW_PASSWORD);

        verify(passwordPolicy).validate(NEW_PASSWORD);
        verify(passwordHasher).hash(NEW_PASSWORD);
        verify(userAccountGateway).update(any(User.class));
        verify(refreshTokenStore).deleteAllForUser(USERNAME);
        verify(metrics).recordSessionRevoked();
        verify(auditEventPublisher).publishAuthEvent(eq("PASSWORD_CHANGED"), eq(USERNAME), any(),
                contains("successfully"));
    }

    @Test
    @DisplayName(" should throw when current password is incorrect")
    void testShouldThrowWhenCurrentPasswordIncorrect() {
        when(userAccountGateway.findByUsernameOrEmail(USERNAME)).thenReturn(Optional.of(user));
        when(passwordHasher.matches(CURRENT_PASSWORD, VALID_HASH)).thenReturn(false);

        assertThatThrownBy(() -> service.changePassword(USERNAME, CURRENT_PASSWORD, NEW_PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessageContaining("Invalid current password");

        verify(metrics).recordLoginFailure();
        verify(auditEventPublisher).publishAuthEvent(eq("PASSWORD_CHANGE_FAILED"), eq(USERNAME), any(),
                contains("Incorrect current password"));
        verifyNoInteractions(refreshTokenStore);
    }

    @Test
    @DisplayName(" should throw when user is not found")
    void testShouldThrowWhenUserNotFound() {
        when(userAccountGateway.findByUsernameOrEmail(USERNAME)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> service.changePassword(USERNAME, CURRENT_PASSWORD, NEW_PASSWORD))
                .isInstanceOf(InvalidCredentialsException.class)
                .hasMessageContaining("User not found");

        verifyNoInteractions(passwordHasher, passwordPolicy, refreshTokenStore);
    }

    @Test
    @DisplayName(" should throw when new password violates PasswordPolicy")
    void testShouldThrowWhenPasswordTooWeak() {
        when(userAccountGateway.findByUsernameOrEmail(USERNAME)).thenReturn(Optional.of(user));
        when(passwordHasher.matches(CURRENT_PASSWORD, VALID_HASH)).thenReturn(true);
        doThrow(new IllegalArgumentException("weak password")).when(passwordPolicy).validate(NEW_PASSWORD);

        assertThatThrownBy(() -> service.changePassword(USERNAME, CURRENT_PASSWORD, NEW_PASSWORD))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("weak password");

        verify(passwordPolicy).validate(NEW_PASSWORD);
        verify(userAccountGateway, never()).update(any());
        verify(refreshTokenStore, never()).deleteAllForUser(any());
        verify(auditEventPublisher, never()).publishAuthEvent(eq("PASSWORD_CHANGED"), any(), any(), any());
    }
}
