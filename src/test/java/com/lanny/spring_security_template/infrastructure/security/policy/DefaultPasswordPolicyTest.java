package com.lanny.spring_security_template.infrastructure.security.policy;

import static org.assertj.core.api.Assertions.*;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

class DefaultPasswordPolicyTest {

    private final DefaultPasswordPolicy policy = new DefaultPasswordPolicy();

    @Test
    @DisplayName("should accept valid complex password")
    void testShouldAcceptValidPassword() {
        assertThatCode(() -> policy.validate("Abcd1234!"))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("should reject password shorter than minimum length")
    void testShouldRejectShortPassword() {
        assertThatThrownBy(() -> policy.validate("Ab1!"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("at least 8 characters");
    }

    @Test
    @DisplayName("should reject password without uppercase letters")
    void testShouldRejectWithoutUppercase() {
        assertThatThrownBy(() -> policy.validate("abcd1234!"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("uppercase");
    }

    @Test
    @DisplayName("should reject password without numbers")
    void testShouldRejectWithoutNumbers() {
        assertThatThrownBy(() -> policy.validate("Abcdefgh!"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("number");
    }

    @Test
    @DisplayName("should reject password without special characters")
    void shouldRejectWithoutSpecialChar() {
        assertThatThrownBy(() -> policy.validate("Abcd1234"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("special symbol");
    }
}
