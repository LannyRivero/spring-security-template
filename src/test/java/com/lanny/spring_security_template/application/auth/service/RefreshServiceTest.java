package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.application.auth.result.JwtResult;

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

    @InjectMocks
    private RefreshService refreshService;

    private static final String REFRESH = "REFRESH_TOKEN_ABC";

    // Helper para crear claims válidos
    private JwtClaimsDTO claims() {
        return new JwtClaimsDTO(
                "lanny",
                "jti-123",
                List.of("refresh_aud"),
                1000L,
                1000L,
                2000L,
                List.of("ROLE_USER"),
                List.of("profile:read"), "refresh");
    }

    @Test
    @DisplayName("refresh() → should return new access token when rotation is disabled")
    void testShouldReturnAccessOnlyWhenRotationDisabled() {
        RefreshCommand cmd = new RefreshCommand(REFRESH);

        JwtClaimsDTO claims = claims();
        JwtResult expected = new JwtResult("ACCESS123", REFRESH, Instant.now().plusSeconds(3600));

        when(tokenProvider.validateAndGetClaims(REFRESH)).thenReturn(Optional.of(claims));
        doNothing().when(validator).validate(claims);
        when(rotationHandler.shouldRotate()).thenReturn(false);
        when(resultFactory.newAccessOnly(claims, REFRESH)).thenReturn(expected);

        JwtResult result = refreshService.refresh(cmd);

        assertThat(result).isEqualTo(expected);

        verify(tokenProvider).validateAndGetClaims(REFRESH);
        verify(validator).validate(claims);
        verify(rotationHandler).shouldRotate();
        verify(resultFactory).newAccessOnly(claims, REFRESH);
        verify(rotationHandler, never()).rotate(any(), any());
    }

    @Test
    @DisplayName("refresh() → should rotate tokens when rotation is enabled")
    void testShouldRotateTokensWhenRotationEnabled() {
        RefreshCommand cmd = new RefreshCommand(REFRESH);

        JwtClaimsDTO claims = claims();
        JwtResult rotated = new JwtResult("ACCESS_NEW", "REFRESH_NEW", Instant.now().plusSeconds(3600));

        when(tokenProvider.validateAndGetClaims(cmd.refreshToken())).thenReturn(Optional.of(claims));
        doNothing().when(validator).validate(claims);
        when(rotationHandler.shouldRotate()).thenReturn(true);
        when(rotationHandler.rotate(claims, REFRESH)).thenReturn(rotated);

        JwtResult result = refreshService.refresh(cmd);

        assertThat(result).isEqualTo(rotated);
    }

    @Test
    @DisplayName("refresh() → should throw when tokenProvider returns empty Optional")
    void testShouldThrowWhenRefreshTokenInvalid() {
        RefreshCommand cmd = new RefreshCommand(REFRESH);

        when(tokenProvider.validateAndGetClaims(REFRESH)).thenReturn(Optional.empty());

        assertThatThrownBy(() -> refreshService.refresh(cmd))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessage("Invalid refresh token");

        verifyNoInteractions(validator, rotationHandler, resultFactory);
    }

    @Test
    @DisplayName("refresh() → should propagate validator exceptions")
    void testShouldPropagateValidatorException() {
        RefreshCommand cmd = new RefreshCommand(REFRESH);

        JwtClaimsDTO claims = claims();

        when(tokenProvider.validateAndGetClaims(REFRESH)).thenReturn(Optional.of(claims));
        doThrow(new IllegalStateException("Expired token")).when(validator).validate(claims);

        assertThatThrownBy(() -> refreshService.refresh(cmd))
                .isInstanceOf(IllegalStateException.class)
                .hasMessage("Expired token");

        verify(rotationHandler, never()).shouldRotate();
        verify(resultFactory, never()).newAccessOnly(any(), any());
    }

    @Test
    @DisplayName("refresh() → should not call rotate when rotationHandler returns false")
    void testShouldNotRotateWhenRotationFalse() {
        RefreshCommand cmd = new RefreshCommand(REFRESH);

        JwtClaimsDTO claims = claims();
        JwtResult expected = new JwtResult("ACCESS123", REFRESH, Instant.now().plusSeconds(3600));

        when(tokenProvider.validateAndGetClaims(REFRESH)).thenReturn(Optional.of(claims));
        doNothing().when(validator).validate(claims);
        when(rotationHandler.shouldRotate()).thenReturn(false);
        when(resultFactory.newAccessOnly(claims, REFRESH)).thenReturn(expected);

        refreshService.refresh(cmd);

        verify(resultFactory).newAccessOnly(claims, REFRESH);
        verify(rotationHandler, never()).rotate(any(), any());
    }
}
