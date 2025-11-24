package com.lanny.spring_security_template.application.auth.result;

import static org.assertj.core.api.Assertions.*;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class MeResultTest {

    @Test
    @DisplayName("Should correctly expose user identity and authorization attributes")
    void shouldExposeFieldsCorrectly() {
        // Arrange
        List<String> roles = List.of("ADMIN", "USER");
        List<String> scopes = List.of("profile:read", "profile:write");

        MeResult me = new MeResult("123", "alice", roles, scopes);

        // Assert
        assertThat(me.userId()).isEqualTo("123");
        assertThat(me.username()).isEqualTo("alice");
        assertThat(me.roles()).containsExactly("ADMIN", "USER");
        assertThat(me.scopes()).containsExactly("profile:read", "profile:write");
    }

    @Test
    @DisplayName("Two MeResult objects with identical values should be equal")
    void equalityShouldWorkCorrectly() {
        List<String> roles = List.of("ADMIN");
        List<String> scopes = List.of("simulation:read");

        MeResult a = new MeResult("1", "bob", roles, scopes);
        MeResult b = new MeResult("1", "bob", roles, scopes);

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    @DisplayName("toString should contain user and authorization fields")
    void toStringShouldContainFields() {
        MeResult me = new MeResult("999", "eva",
                List.of("USER"),
                List.of("profile:read"));

        assertThat(me.toString())
                .contains("999")
                .contains("eva")
                .contains("USER")
                .contains("profile:read");
    }
}
