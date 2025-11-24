package com.lanny.spring_security_template.domain.valueobject;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class EmailAddressTest {

    @Test
    @DisplayName("Should create EmailAddress when raw value is valid")
    void shouldCreateEmail_whenRawIsValid() {
        EmailAddress email = EmailAddress.of("Test@Example.com");

        assertThat(email.value()).isEqualTo("test@example.com");
    }

    @Test
    @DisplayName("Should throw exception for null or blank email")
    void shouldThrow_whenEmailIsNullOrBlank() {
        assertThatThrownBy(() -> EmailAddress.of(null))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> EmailAddress.of(" "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should throw exception when email has no @ symbol")
    void shouldThrow_whenEmailHasInvalidFormat() {
        assertThatThrownBy(() -> EmailAddress.of("invalid-email"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should be equal for normalized emails")
    void shouldBeEqual_whenEmailsNormalizeToSameValue() {
        EmailAddress e1 = EmailAddress.of("ADMIN@MAIL.COM");
        EmailAddress e2 = EmailAddress.of("admin@mail.com");

        assertThat(e1).isEqualTo(e2);
    }
}
