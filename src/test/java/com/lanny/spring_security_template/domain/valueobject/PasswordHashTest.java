package com.lanny.spring_security_template.domain.valueobject;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class PasswordHashTest {

    @Test
    @DisplayName("Should create PasswordHash when hash is valid")
    void shouldCreatePasswordHash_whenValid() {
        PasswordHash hash = PasswordHash.of("$2a$10$abcdefghijklmnopqrstuv");

        assertThat(hash.value()).isEqualTo("$2a$10$abcdefghijklmnopqrstuv");
    }

    @Test
    @DisplayName("Should throw exception for null or blank hash")
    void shouldThrow_whenHashIsNullOrBlank() {
        assertThatThrownBy(() -> PasswordHash.of(null))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> PasswordHash.of(" "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should be equal when hash values match")
    void shouldBeEqual_whenValuesMatch() {
        PasswordHash p1 = PasswordHash.of("abc");
        PasswordHash p2 = PasswordHash.of("abc");

        assertThat(p1).isEqualTo(p2);
    }
}
