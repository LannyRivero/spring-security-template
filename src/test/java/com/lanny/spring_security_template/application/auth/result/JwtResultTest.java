package com.lanny.spring_security_template.application.auth.result;

import static org.assertj.core.api.Assertions.*;

import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class JwtResultTest {

    @Test
    @DisplayName("Should correctly store and expose all JWT result fields")
    void shouldExposeFieldsCorrectly() {
        // Arrange
        Instant now = Instant.parse("2030-01-01T00:00:00Z");
        JwtResult result = new JwtResult("access123", "refresh456", now);

        // Assert
        assertThat(result.accessToken()).isEqualTo("access123");
        assertThat(result.refreshToken()).isEqualTo("refresh456");
        assertThat(result.expiresAt()).isEqualTo(now);
    }

    @Test
    @DisplayName("Two JwtResult objects with same data should be equal")
    void equalityShouldWorkCorrectly() {
        // Arrange
        Instant exp = Instant.parse("2035-02-02T00:00:00Z");
        JwtResult a = new JwtResult("a", "b", exp);
        JwtResult b = new JwtResult("a", "b", exp);

        // Assert
        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    @DisplayName("toString should contain the relevant fields")
    void toStringShouldContainFields() {
        Instant exp = Instant.now();
        JwtResult result = new JwtResult("acc", "ref", exp);

        assertThat(result.toString())
                .contains("acc")
                .contains("ref")
                .contains(exp.toString());
    }
}
