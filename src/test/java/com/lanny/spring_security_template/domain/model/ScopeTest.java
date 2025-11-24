package com.lanny.spring_security_template.domain.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class ScopeTest {

    @Test
    @DisplayName("Should create Scope when format is valid")
    void shouldCreateScope_whenValidFormat() {
        Scope scope = Scope.of("profile:read");

        assertThat(scope.name()).isEqualTo("profile:read");
        assertThat(scope.resource()).isEqualTo("profile");
        assertThat(scope.action()).isEqualTo("read");
    }

    @Test
    @DisplayName("Should throw exception when format is invalid")
    void shouldThrow_whenInvalidFormat() {
        assertThatThrownBy(() -> Scope.of("invalid"))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> Scope.of(":wrong"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should be equal when two scopes have same name")
    void shouldBeEqual_whenNamesMatch() {
        Scope s1 = Scope.of("user:write");
        Scope s2 = Scope.of("user:write");

        assertThat(s1).isEqualTo(s2);
    }
}
