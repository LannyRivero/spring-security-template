package com.lanny.spring_security_template.application.auth.command;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.*;

class RegisterCommandTest {

    @Test
    @DisplayName("Should correctly expose username, email, password, roles and scopes")
    void shouldExposeFieldsCorrectly() {
        // Arrange
        List<String> roles = List.of("USER", "ADMIN");
        List<String> scopes = List.of("profile:read", "profile:write");

        RegisterCommand cmd = new RegisterCommand(
                "alice",
                "alice@example.com",
                "Password$123",
                roles,
                scopes);

        // Assert
        assertThat(cmd.username()).isEqualTo("alice");
        assertThat(cmd.email()).isEqualTo("alice@example.com");
        assertThat(cmd.rawPassword()).isEqualTo("Password$123");
        assertThat(cmd.roles()).containsExactly("USER", "ADMIN");
        assertThat(cmd.scopes()).containsExactly("profile:read", "profile:write");
    }

    @Test
    @DisplayName("Two RegisterCommand objects with same data should be equal")
    void equalityShouldWork() {
        List<String> roles = List.of("USER");
        List<String> scopes = List.of("profile:read");

        RegisterCommand a = new RegisterCommand(
                "bob",
                "b@b.com",
                "pass",
                roles,
                scopes);

        RegisterCommand b = new RegisterCommand(
                "bob",
                "b@b.com",
                "pass",
                roles,
                scopes);

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    @DisplayName("toString should include core fields")
    void toStringShouldContainFields() {
        RegisterCommand cmd = new RegisterCommand(
                "eva",
                "eva@test.com",
                "pass",
                List.of("USER"),
                List.of("profile:read"));

        assertThat(cmd.toString())
                .contains("eva")
                .contains("eva@test.com")
                .contains("USER")
                .contains("profile:read");
    }
}
