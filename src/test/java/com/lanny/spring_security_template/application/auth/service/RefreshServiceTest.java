package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;

import org.junit.jupiter.api.*;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.*;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Comprehensive test suite for {@link RefreshService}.
 * Focuses on orchestrating validation, rotation and access renewal flows.
 */
@ExtendWith(MockitoExtension.class)
class RefreshServiceTest {

    @Mock private TokenProvider tokenProvider;
    @Mock private RefreshTokenValidator validator;
    @Mock private TokenRotationHandler rotationHandler;
    @Mock private TokenRefreshResultFactory resultFactory;

    @InjectMocks private RefreshService refreshService;

    private static final String REFRESH_TOKEN = "valid-refresh-token";
    private final JwtClaimsDTO claims = new JwtClaimsDTO(
            "lanny",
            "refresh-jti-001",
            List.of("refresh_audience"),
            1_000L,
            1_000L,
            2_000L,
            List.of("ROLE_USER"),
            List.of("profile:read")
    );

    // Helper to avoid boilerplate
    private RefreshCommand cmd() {
        return new RefreshCommand(REFRESH_TOKEN);
    }

    @Test
    @DisplayName(" should generate new access-only token when rotation disabled")
    void testShouldGenerateAccessOnlyWhenRotationDisabled() {
        // given
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        doNothing().when(validator).validate(claims);
        when(rotationHandler.shouldRotate()).thenReturn(false);

        JwtResult expected = new JwtResult("new-access", REFRESH_TOKEN, Instant.now());
        when(resultFactory.newAccessOnly(claims, REFRESH_TOKEN)).thenReturn(expected);

        // when
        JwtResult result = refreshService.refresh(cmd());

        // then
        assertThat(result).isEqualTo(expected);

        verify(validator).validate(claims);
        verify(rotationHandler).shouldRotate();
        verify(rotationHandler, never()).rotate(any());
        verify(resultFactory).newAccessOnly(claims, REFRESH_TOKEN);
    }

    @Test
    @DisplayName(" should rotate refresh token when rotation enabled")
    void testShouldRotateWhenEnabled() {
        // given
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        doNothing().when(validator).validate(claims);
        when(rotationHandler.shouldRotate()).thenReturn(true);

        JwtResult rotated = new JwtResult("new-access", "new-refresh", Instant.now());
        when(rotationHandler.rotate(claims)).thenReturn(rotated);

        // when
        JwtResult result = refreshService.refresh(cmd());

        // then
        assertThat(result).isEqualTo(rotated);

        verify(validator).validate(claims);
        verify(rotationHandler).shouldRotate();
        verify(rotationHandler).rotate(claims);
        verify(resultFactory, never()).newAccessOnly(any(), any());
    }

    @Test
    @DisplayName(" should throw when refresh token is invalid (no claims returned)")
    void testShouldThrowWhenInvalidToken() {
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshService.refresh(cmd()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid refresh token");

        verifyNoInteractions(validator, rotationHandler, resultFactory);
    }

    @Test
    @DisplayName(" should throw when validator fails on invalid claims")
    void testShouldThrowWhenValidatorFails() {
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        doThrow(new IllegalArgumentException("invalid audience")).when(validator).validate(claims);

        assertThatThrownBy(() -> refreshService.refresh(cmd()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("invalid audience");

        verify(validator).validate(claims);
        verify(rotationHandler, never()).shouldRotate();
        verify(rotationHandler, never()).rotate(any());
        verify(resultFactory, never()).newAccessOnly(any(), any());
    }

    @Test
    @DisplayName(" should propagate errors thrown during rotation")
    void testShouldPropagateRotationFailure() {
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        doNothing().when(validator).validate(claims);
        when(rotationHandler.shouldRotate()).thenReturn(true);
        when(rotationHandler.rotate(claims)).thenThrow(new IllegalStateException("Rotation failed"));

        assertThatThrownBy(() -> refreshService.refresh(cmd()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Rotation failed");

        verify(validator).validate(claims);
        verify(rotationHandler).shouldRotate();
        verify(rotationHandler).rotate(claims);
        verify(resultFactory, never()).newAccessOnly(any(), any());
    }
}

