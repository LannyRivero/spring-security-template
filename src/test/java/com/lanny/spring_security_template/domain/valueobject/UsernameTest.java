package com.lanny.spring_security_template.domain.valueobject;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.*;

class UsernameTest {

    @Test
    @DisplayName("Should create Username when raw value is valid")
    void shouldCreateUsername_whenRawIsValid() {
        Username username = Username.of("JohnDoe");

        assertThat(username.value()).isEqualTo("johndoe");
    }

    @Test
    @DisplayName("Should trim and lowercase Username")
    void shouldNormalizeUsername_whenRawHasSpacesOrUppercase() {
        Username username = Username.of("   Alice   ");

        assertThat(username.value()).isEqualTo("alice");
    }

    @Test
    @DisplayName("Should throw exception when raw username is null or blank")
    void shouldThrow_whenRawIsNullOrBlank() {
        assertThatThrownBy(() -> Username.of(null))
                .isInstanceOf(IllegalArgumentException.class);

        assertThatThrownBy(() -> Username.of(" "))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should consider two Username objects equal when normalized values match")
    void shouldBeEqual_whenValuesMatch() {
        Username u1 = Username.of("Bob");
        Username u2 = Username.of("bob");

        assertThat(u1).isEqualTo(u2);
        assertThat(u1.hashCode()).isEqualTo(u2.hashCode());
    }
}

