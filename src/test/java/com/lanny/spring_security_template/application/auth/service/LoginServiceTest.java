package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RefreshService} after refactoring to Clean Architecture.
 * Verifies orchestration between validator, rotation handler, and result factory.
 */
@ExtendWith(MockitoExtension.class)
class RefreshServiceTest {

    @Mock private TokenProvider tokenProvider;
    @Mock private RefreshTokenValidator validator;
    @Mock private TokenRotationHandler rotationHandler;
    @Mock private TokenRefreshResultFactory resultFactory;

    @InjectMocks private RefreshService refreshService;

    private static final String REFRESH_TOKEN = "refresh-123";
    private static final String ACCESS_TOKEN = "access-456";

    private final JwtClaimsDTO claims = new JwtClaimsDTO(
            "lanny",
            "jti-999",
            List.of("refresh_audience"),
            1000L,
            1000L,
            2000L,
            List.of("ROLE_USER"),
            List.of("profile:read")
    );

    @Test
    @DisplayName(" should delegate to rotation handler when rotation is enabled")
    void testShouldRefreshWithRotation() {
        // Arrange
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        when(rotationHandler.shouldRotate()).thenReturn(true);

        JwtResult expected = new JwtResult(ACCESS_TOKEN, REFRESH_TOKEN, Instant.now());
        when(rotationHandler.rotate(claims)).thenReturn(expected);

        // Act
        JwtResult result = refreshService.refresh(new RefreshCommand(REFRESH_TOKEN));

        // Assert
        assertThat(result).isEqualTo(expected);

        verify(validator).validate(claims);
        verify(rotationHandler).rotate(claims);
        verifyNoInteractions(resultFactory);
    }

    @Test
    @DisplayName(" should generate new access token without rotation")
    void testShouldRefreshWithoutRotation() {
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        when(rotationHandler.shouldRotate()).thenReturn(false);

        JwtResult expected = new JwtResult(ACCESS_TOKEN, REFRESH_TOKEN, Instant.now());
        when(resultFactory.newAccessOnly(claims, REFRESH_TOKEN)).thenReturn(expected);

        JwtResult result = refreshService.refresh(new RefreshCommand(REFRESH_TOKEN));

        assertThat(result).isEqualTo(expected);

        verify(validator).validate(claims);
        verify(resultFactory).newAccessOnly(claims, REFRESH_TOKEN);
        verifyNoInteractions(rotationHandler);
    }

    @Test
    @DisplayName(" should throw when tokenProvider returns empty (invalid token)")
    void testShouldThrowWhenInvalidToken() {
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshService.refresh(new RefreshCommand(REFRESH_TOKEN)))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid refresh token");

        verifyNoInteractions(validator, rotationHandler, resultFactory);
    }
}

