package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.TokenBlacklistGateway;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RefreshTokenValidator}.
 * Covers audience, existence, and revocation checks.
 */
class RefreshTokenValidatorTest {

    private final RefreshTokenStore refreshTokenStore = mock(RefreshTokenStore.class);
    private final TokenBlacklistGateway blacklist = mock(TokenBlacklistGateway.class);
    private final SecurityJwtProperties props = mock(SecurityJwtProperties.class);

    private final RefreshTokenValidator validator = new RefreshTokenValidator(refreshTokenStore, blacklist, props);

    private JwtClaimsDTO createClaims(String audValue) {
        return new JwtClaimsDTO(
                "user123",
                "jti-001",
                List.of(audValue),
                1000L,
                1000L,
                2000L,
                List.of("ROLE_USER"),
                List.of("simulation:read"));
    }

    @Test
    @DisplayName(" should validate successfully when audience, existence and blacklist are valid")
    void shouldValidateSuccessfully() {
        // Arrange
        JwtClaimsDTO claims = createClaims("refresh-service");
        when(props.refreshAudience()).thenReturn("refresh-service");
        when(refreshTokenStore.exists("jti-001")).thenReturn(true);
        when(blacklist.isRevoked("jti-001")).thenReturn(false);

        // Act & Assert
        assertThatCode(() -> validator.validate(claims))
                .doesNotThrowAnyException();

        verify(refreshTokenStore).exists("jti-001");
        verify(blacklist).isRevoked("jti-001");
    }

    @Test
    @DisplayName(" should throw when audience is invalid")
    void shouldThrowWhenInvalidAudience() {
        JwtClaimsDTO claims = createClaims("wrong-service");
        when(props.refreshAudience()).thenReturn("refresh-service");

        assertThatThrownBy(() -> validator.validate(claims))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Invalid refresh token audience");

        verifyNoInteractions(refreshTokenStore);
        verifyNoInteractions(blacklist);
    }

    @Test
    @DisplayName(" should throw when token not found in store")
    void shouldThrowWhenTokenNotFound() {
        JwtClaimsDTO claims = createClaims("refresh-service");
        when(props.refreshAudience()).thenReturn("refresh-service");
        when(refreshTokenStore.exists("jti-001")).thenReturn(false);

        assertThatThrownBy(() -> validator.validate(claims))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Refresh token not found");

        verify(refreshTokenStore).exists("jti-001");
        verifyNoInteractions(blacklist);
    }

    @Test
    @DisplayName(" should throw when token is revoked or re-used")
    void shouldThrowWhenTokenRevoked() {
        JwtClaimsDTO claims = createClaims("refresh-service");
        when(props.refreshAudience()).thenReturn("refresh-service");
        when(refreshTokenStore.exists("jti-001")).thenReturn(true);
        when(blacklist.isRevoked("jti-001")).thenReturn(true);

        assertThatThrownBy(() -> validator.validate(claims))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("Refresh token revoked or re-used");

        verify(refreshTokenStore).exists("jti-001");
        verify(blacklist).isRevoked("jti-001");
    }
}
