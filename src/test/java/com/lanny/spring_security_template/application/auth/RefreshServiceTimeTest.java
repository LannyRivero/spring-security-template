package com.lanny.spring_security_template.application.auth;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.service.RefreshService;
import com.lanny.spring_security_template.application.auth.service.RefreshTokenValidator;
import com.lanny.spring_security_template.application.auth.service.TokenRefreshResultFactory;
import com.lanny.spring_security_template.application.auth.service.TokenRotationHandler;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

/**
 * Integration-style unit test for the new RefreshService orchestration.
 * Focuses on correct coordination of validator, rotationHandler, and factory.
 */
class RefreshServiceTimeTest {

        @Test
        @DisplayName(" should refresh tokens successfully before expiration (no rotation)")
        void testShouldRefreshBeforeExpiration() {
                // Arrange
                TokenProvider tokenProvider = mock(TokenProvider.class);
                RefreshTokenValidator validator = mock(RefreshTokenValidator.class);
                TokenRotationHandler rotationHandler = mock(TokenRotationHandler.class);
                TokenRefreshResultFactory resultFactory = mock(TokenRefreshResultFactory.class);

                RefreshService service = new RefreshService(
                                tokenProvider, validator, rotationHandler, resultFactory);

                String refreshToken = "valid-refresh-token";

                JwtClaimsDTO claims = new JwtClaimsDTO(
                                "alice",
                                "jti-123",
                                List.of("refresh_audience"),
                                1000L,
                                1000L,
                                2000L,
                                List.of("ROLE_USER"),
                                List.of("profile:read"));

                // Simulamos validación correcta y no rotación
                when(tokenProvider.validateAndGetClaims(refreshToken)).thenReturn(Optional.of(claims));
                when(rotationHandler.shouldRotate()).thenReturn(false);

                JwtResult expected = new JwtResult("new-access-token", refreshToken, Instant.now());
                when(resultFactory.newAccessOnly(claims, refreshToken)).thenReturn(expected);

                // Act
                JwtResult result = service.refresh(new RefreshCommand(refreshToken));

                // Assert
                assertThat(result).isEqualTo(expected);
                verify(validator).validate(claims);
                verify(resultFactory).newAccessOnly(claims, refreshToken);
                verify(rotationHandler).shouldRotate();
                verify(rotationHandler, never()).rotate(any());

        }

        @Test
        @DisplayName(" should throw when refresh token is invalid (no claims)")
        void testRefreshShouldFailWhenTokenInvalid() {
                // Arrange
                TokenProvider tokenProvider = mock(TokenProvider.class);
                RefreshTokenValidator validator = mock(RefreshTokenValidator.class);
                TokenRotationHandler rotationHandler = mock(TokenRotationHandler.class);
                TokenRefreshResultFactory resultFactory = mock(TokenRefreshResultFactory.class);

                RefreshService service = new RefreshService(
                                tokenProvider, validator, rotationHandler, resultFactory);

                when(tokenProvider.validateAndGetClaims("invalid-token"))
                                .thenReturn(Optional.empty());

                // Act + Assert
                assertThatThrownBy(() -> service.refresh(new RefreshCommand("invalid-token")))
                                .isInstanceOf(IllegalArgumentException.class)
                                .hasMessage("Invalid refresh token");

                verifyNoInteractions(validator, rotationHandler, resultFactory);
        }
}
