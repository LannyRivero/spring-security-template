package com.lanny.spring_security_template.application.auth.command;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class RefreshCommandTest {

    @Test
    @DisplayName("Should expose refreshToken correctly")
    void shouldExposeFieldCorrectly() {
        RefreshCommand cmd = new RefreshCommand("refresh-123");

        assertThat(cmd.refreshToken()).isEqualTo("refresh-123");
    }

    @Test
    @DisplayName("Two RefreshCommand objects with same token should be equal")
    void equalityShouldWork() {
        RefreshCommand a = new RefreshCommand("abc");
        RefreshCommand b = new RefreshCommand("abc");

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    @DisplayName("toString should contain refresh token")
    void toStringShouldContainField() {
        RefreshCommand cmd = new RefreshCommand("zzz");

        assertThat(cmd.toString()).contains("zzz");
    }
}
