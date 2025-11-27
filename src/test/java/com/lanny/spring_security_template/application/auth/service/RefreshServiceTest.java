package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.event.SecurityEvent;
import com.lanny.spring_security_template.domain.time.ClockProvider;

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
 * ✅ Unit tests for {@link RefreshService}.
 *
 * <p>
 * Verifies orchestration of refresh-token flow including:
 * <ul>
 * <li>Token validation and claim extraction</li>
 * <li>Rotation handling logic (enabled / disabled)</li>
 * <li>Audit event publishing and MDC trace context</li>
 * <li>Error propagation on invalid tokens or failed rotation</li>
 * </ul>
 * </p>
 *
 * <h2>Dependencies under test</h2>
 * <ul>
 * <li>{@link TokenProvider}</li>
 * <li>{@link RefreshTokenValidator}</li>
 * <li>{@link TokenRotationHandler}</li>
 * <li>{@link TokenRefreshResultFactory}</li>
 * <li>{@link ClockProvider}</li>
 * <li>{@link AuditEventPublisher}</li>
 * </ul>
 */
@ExtendWith(MockitoExtension.class)
class RefreshServiceTest {

    @Mock
    private TokenProvider tokenProvider;
    @Mock
    private RefreshTokenValidator validator;
    @Mock
    private TokenRotationHandler rotationHandler;
    @Mock
    private TokenRefreshResultFactory resultFactory;
    @Mock
    private ClockProvider clockProvider;
    @Mock
    private AuditEventPublisher auditEventPublisher;

    @InjectMocks
    private RefreshService refreshService;

    private static final String REFRESH_TOKEN = "valid-refresh-token";

    private final JwtClaimsDTO claims = new JwtClaimsDTO(
            "lanny",
            "refresh-jti-001",
            List.of("refresh_audience"),
            1_000L,
            1_000L,
            2_000L,
            List.of("ROLE_USER"),
            List.of("profile:read"));

    private RefreshCommand cmd() {
        return new RefreshCommand(REFRESH_TOKEN);
    }

    @Test
    @DisplayName(" Should generate new access-only token when rotation disabled")
    void testShouldGenerateAccessOnlyWhenRotationDisabled() {
        // Arrange
        Instant now = Instant.now();
        JwtResult expected = new JwtResult("new-access", REFRESH_TOKEN, now);

        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        doNothing().when(validator).validate(claims);
        when(rotationHandler.shouldRotate()).thenReturn(false);
        when(resultFactory.newAccessOnly(claims, REFRESH_TOKEN)).thenReturn(expected);
        when(clockProvider.now()).thenReturn(now);

        // Act
        JwtResult result = refreshService.refresh(cmd());

        // Assert
        assertThat(result).isEqualTo(expected);

        verify(validator).validate(claims);
        verify(rotationHandler).shouldRotate();
        verify(resultFactory).newAccessOnly(claims, REFRESH_TOKEN);
        verify(rotationHandler, never()).rotate(any());
        verify(auditEventPublisher).publishAuthEvent(
                eq(SecurityEvent.TOKEN_REFRESH.name()),
                eq("lanny"),
                eq(now),
                contains("refreshed without rotation"));
    }

    @Test
    @DisplayName(" Should rotate refresh token when rotation enabled")
    void testShouldRotateWhenEnabled() {
        // Arrange
        Instant now = Instant.now();
        JwtResult rotated = new JwtResult("new-access", "new-refresh", now);

        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        doNothing().when(validator).validate(claims);
        when(rotationHandler.shouldRotate()).thenReturn(true);
        when(rotationHandler.rotate(claims)).thenReturn(rotated);
        when(clockProvider.now()).thenReturn(now);

        // Act
        JwtResult result = refreshService.refresh(cmd());

        // Assert
        assertThat(result).isEqualTo(rotated);

        verify(validator).validate(claims);
        verify(rotationHandler).shouldRotate();
        verify(rotationHandler).rotate(claims);
        verify(resultFactory, never()).newAccessOnly(any(), any());
        verify(auditEventPublisher).publishAuthEvent(
                eq(SecurityEvent.TOKEN_ROTATED.name()),
                eq("lanny"),
                eq(now),
                contains("new session issued"));
    }

    @Test
    @DisplayName(" Should throw when refresh token is invalid (no claims returned)")
    void testShouldThrowWhenInvalidToken() {
        // Arrange
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.empty());

        // Act & Assert
        assertThatThrownBy(() -> refreshService.refresh(cmd()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid refresh token");

        verifyNoInteractions(validator, rotationHandler, resultFactory, auditEventPublisher);
    }

    @Test
    @DisplayName(" Should throw when validator fails on invalid claims")
    void testShouldThrowWhenValidatorFails() {
        // Arrange
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        doThrow(new IllegalArgumentException("invalid audience")).when(validator).validate(claims);

        // Act & Assert
        assertThatThrownBy(() -> refreshService.refresh(cmd()))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("invalid audience");

        verify(validator).validate(claims);
        verify(rotationHandler, never()).shouldRotate();
        verifyNoInteractions(auditEventPublisher);
    }

    @Test
    @DisplayName(" Should propagate errors thrown during rotation")
    void testShouldPropagateRotationFailure() {
        // Arrange
        when(tokenProvider.validateAndGetClaims(REFRESH_TOKEN)).thenReturn(Optional.of(claims));
        doNothing().when(validator).validate(claims);
        when(rotationHandler.shouldRotate()).thenReturn(true);
        when(rotationHandler.rotate(claims)).thenThrow(new IllegalStateException("Rotation failed"));

        // Act & Assert
        assertThatThrownBy(() -> refreshService.refresh(cmd()))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Rotation failed");

        verify(validator).validate(claims);
        verify(rotationHandler).shouldRotate();
        verify(rotationHandler).rotate(claims);
        verifyNoInteractions(auditEventPublisher);
    }
}
