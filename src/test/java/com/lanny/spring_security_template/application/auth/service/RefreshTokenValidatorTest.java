package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.policy.RefreshTokenPolicy;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;

/**
 * Unit tests for {@link RefreshTokenValidator}.
 * Covers audience, existence, and revocation checks.
 */
class RefreshTokenValidatorTest {

    private final RefreshTokenPolicy policy = mock(RefreshTokenPolicy.class);

    private final RefreshTokenValidator validator = new RefreshTokenValidator(policy);

    private JwtClaimsDTO createClaims(String audValue) {
        return new JwtClaimsDTO(
                "user123",
                "jti-001",
                List.of(audValue),
                1000L,
                1000L,
                2000L,
                List.of("ROLE_USER"),
                List.of("simulation:read"),
                "refresh");
    }

    @Test
    @DisplayName(" should validate successfully when audience, existence and blacklist are valid")
    void testShouldValidateSuccessfully() {
        // Arrange
        JwtClaimsDTO claims = createClaims("refresh-service");
        when(policy.expectedRefreshAudience()).thenReturn("refresh-service");

        // Act & Assert
        assertThatCode(() -> validator.validate(claims))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName(" should throw when audience is invalid")
    void testShouldThrowWhenInvalidAudience() {
        JwtClaimsDTO claims = createClaims("wrong-service");
        when(policy.expectedRefreshAudience()).thenReturn("refresh-service");

        assertThatThrownBy(() -> validator.validate(claims))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid refresh token audience");

    }

    @Test
    @DisplayName(" should throw when token not found in store")
    void testShouldThrowWhenTokenNotFound() {
        JwtClaimsDTO claims = createClaims("refresh-service");
        when(policy.expectedRefreshAudience()).thenReturn("refresh-service");

        assertThatThrownBy(() -> validator.validate(claims))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Refresh token not found");

    }

    @Test
    @DisplayName(" should throw when token is revoked or re-used")
    void testShouldThrowWhenTokenRevoked() {
        JwtClaimsDTO claims = createClaims("refresh-service");
        when(policy.expectedRefreshAudience()).thenReturn("refresh-service");

        assertThatThrownBy(() -> validator.validate(claims))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Refresh token revoked or re-used");

    }

    @Test
    @DisplayName(" should throw when audience is null")
    void testShouldThrowWhenAudienceNull() {
        JwtClaimsDTO claims = new JwtClaimsDTO("user123", "jti-001", null, 1000L, 1000L, 2000L, List.of(), List.of(),
                "refresh");
        when(policy.expectedRefreshAudience()).thenReturn("refresh-service");

        assertThatThrownBy(() -> validator.validate(claims))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid refresh token audience");
    }
}