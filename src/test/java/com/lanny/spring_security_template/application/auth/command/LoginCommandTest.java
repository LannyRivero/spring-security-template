package com.lanny.spring_security_template.application.auth.command;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class LoginCommandTest {

    @Test
    @DisplayName("Should correctly expose username and password fields")
    void shouldExposeFieldsCorrectly() {
        // Arrange
        LoginCommand cmd = new LoginCommand("alice", "Secret123!");

        // Assert
        assertThat(cmd.username()).isEqualTo("alice");
        assertThat(cmd.password()).isEqualTo("Secret123!");
    }

    @Test
    @DisplayName("Two LoginCommand objects with same data should be equal")
    void equalityShouldWork() {
        LoginCommand a = new LoginCommand("user", "pass");
        LoginCommand b = new LoginCommand("user", "pass");

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    @DisplayName("toString should include both fields")
    void toStringShouldIncludeValues() {
        LoginCommand cmd = new LoginCommand("u", "p");

        assertThat(cmd.toString())
                .contains("u")
                .contains("p");
    }
}
