package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.UserId;
import com.lanny.spring_security_template.domain.valueobject.Username;
import com.lanny.spring_security_template.infrastructure.mapper.DomainModelMapper;

class ChangePasswordServiceTest {

        private UserAccountGateway userAccountGateway;
        private RefreshTokenStore refreshTokenStore;
        private PasswordHasher passwordHasher;
        private PasswordPolicy passwordPolicy;

        private ChangePasswordService service;

        private static final String USERNAME = "lanny";
        private static final String CURRENT_PASSWORD = "OldPass1!";
        private static final String NEW_PASSWORD = "NewPass1!";

        // MUST satisfy PasswordHash.of() → empieza con '$' y es largo
        private static final String VALID_HASH = "$2a$10$abcdefghijklmnopqrstuv1234567890abcdefghiJKLMNOpq";

        private User user;

        @BeforeEach
        void setUp() {
                userAccountGateway = mock(UserAccountGateway.class);
                refreshTokenStore = mock(RefreshTokenStore.class);
                passwordHasher = mock(PasswordHasher.class);
                passwordPolicy = mock(PasswordPolicy.class);

                service = new ChangePasswordService(
                                userAccountGateway,
                                refreshTokenStore,
                                passwordHasher,
                                passwordPolicy);

                user = User.rehydrate(
                                UserId.newId(),
                                Username.of(USERNAME),
                                EmailAddress.of("user@example.com"),
                                PasswordHash.of(VALID_HASH),
                                UserStatus.ACTIVE,
                                DomainModelMapper.toRoles(List.of("ROLE_USER")),
                                DomainModelMapper.toScopes(List.of("read:profile")));
        }

        // -------------------------------------------------------------------------
        @Test
        @DisplayName("testShouldChangePasswordSuccessfully → update user & invalidate sessions")
        void testShouldChangePasswordSuccessfully() {

                // Arrange
                when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                                .thenReturn(Optional.of(user));

                when(passwordHasher.matches(CURRENT_PASSWORD, VALID_HASH))
                                .thenReturn(true);

                // new hash MUST be valid for PasswordHash.of()
                String newHashValue = "$2b$10$NEWNEWNEWVALIDHASH1234567890ABCDE";
                when(passwordHasher.hash(NEW_PASSWORD)).thenReturn(newHashValue);

                // Act
                service.changePassword(USERNAME, CURRENT_PASSWORD, NEW_PASSWORD);

                // Assert
                verify(passwordPolicy).validate(NEW_PASSWORD);
                verify(passwordHasher).hash(NEW_PASSWORD);

                // Capture the user passed to update()
                verify(userAccountGateway)
                                .update(argThat(updated -> updated.passwordHash().value().equals(newHashValue)));

                verify(refreshTokenStore).deleteAllForUser(USERNAME);
        }

        // -------------------------------------------------------------------------
        @Test
        @DisplayName("testShouldThrowWhenCurrentPasswordIncorrect")
        void testShouldThrowWhenCurrentPasswordIncorrect() {

                when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                                .thenReturn(Optional.of(user));

                when(passwordHasher.matches(CURRENT_PASSWORD, VALID_HASH))
                                .thenReturn(false);

                assertThatThrownBy(() -> service.changePassword(USERNAME, CURRENT_PASSWORD, NEW_PASSWORD))
                                .isInstanceOf(InvalidCredentialsException.class)
                                .hasMessageContaining("Invalid current password");

                verify(passwordHasher).matches(CURRENT_PASSWORD, VALID_HASH);
                verifyNoInteractions(passwordPolicy);
                verify(userAccountGateway, never()).update(any());
                verify(refreshTokenStore, never()).deleteAllForUser(any());
        }

        // -------------------------------------------------------------------------
        @Test
        @DisplayName("testShouldThrowWhenUserNotFound")
        void testShouldThrowWhenUserNotFound() {

                when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                                .thenReturn(Optional.empty());

                assertThatThrownBy(() -> service.changePassword(USERNAME, CURRENT_PASSWORD, NEW_PASSWORD))
                                .isInstanceOf(InvalidCredentialsException.class)
                                .hasMessage("Invalid current password");

                verify(userAccountGateway).findByUsernameOrEmail(USERNAME);
                verifyNoInteractions(passwordHasher, passwordPolicy, refreshTokenStore);
        }

        // -------------------------------------------------------------------------
        @Test
        @DisplayName("testShouldThrowWhenPasswordViolatesPolicy")
        void testShouldThrowWhenPasswordViolatesPolicy() {

                when(userAccountGateway.findByUsernameOrEmail(USERNAME))
                                .thenReturn(Optional.of(user));

                when(passwordHasher.matches(CURRENT_PASSWORD, VALID_HASH))
                                .thenReturn(true);

                doThrow(new IllegalArgumentException("weak password"))
                                .when(passwordPolicy)
                                .validate(NEW_PASSWORD);

                assertThatThrownBy(() -> service.changePassword(USERNAME, CURRENT_PASSWORD, NEW_PASSWORD))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessageContaining("weak password");

                verify(passwordPolicy).validate(NEW_PASSWORD);
                verifyNoInteractions(refreshTokenStore);
                verify(userAccountGateway, never()).update(any());
        }
}
