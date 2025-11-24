package com.lanny.spring_security_template.domain.exception;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for domain-level authentication exceptions.
 *
 * <p>
 * These tests ensure:
 * </p>
 * - Correct internal error codes
 * - Stable behavior for message construction
 * - Consistency across all exception types
 */
class DomainExceptionsTest {

    @Test
    @DisplayName("InvalidCredentialsException should expose correct error code")
    void shouldExposeCorrectCode_whenInvalidCredentialsExceptionIsThrown() {
        InvalidCredentialsException ex = new InvalidCredentialsException();

        assertThat(ex.errorCode()).isEqualTo("ERR-AUTH-001");
        assertThat(ex.getMessage()).isEqualTo("Invalid username or password");
    }

    @Test
    @DisplayName("UserLockedException should expose correct error code")
    void shouldExposeCorrectCode_whenUserLockedExceptionIsThrown() {
        UserLockedException ex = new UserLockedException();

        assertThat(ex.errorCode()).isEqualTo("ERR-AUTH-002");
        assertThat(ex.getMessage()).isEqualTo("User account is locked");
    }

    @Test
    @DisplayName("UserDisabledException should expose correct error code")
    void shouldExposeCorrectCode_whenUserDisabledExceptionIsThrown() {
        UserDisabledException ex = new UserDisabledException();

        assertThat(ex.errorCode()).isEqualTo("ERR-AUTH-003");
        assertThat(ex.getMessage()).isEqualTo("User account is disabled");
    }

    @Test
    @DisplayName("UserDeletedException should expose correct error code")
    void shouldExposeCorrectCode_whenUserDeletedExceptionIsThrown() {
        UserDeletedException ex = new UserDeletedException();

        assertThat(ex.errorCode()).isEqualTo("ERR-AUTH-004");
        assertThat(ex.getMessage()).isEqualTo("User account has been deleted");
    }

    @Test
    @DisplayName("Exceptions should allow custom messages when explicitly provided")
    void shouldUseCustomMessage_whenProvided() {
        var ex = new InvalidCredentialsException("Custom message");

        assertThat(ex.errorCode()).isEqualTo("ERR-AUTH-001");
        assertThat(ex.getMessage()).isEqualTo("Custom message");
    }
}
