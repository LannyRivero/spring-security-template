package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

/**
 * Response containing JWT tokens after authentication or refresh.
 */
@Schema(name = "AuthResponse", description = "Response containing access and refresh tokens with expiration.")
public record AuthResponse(

        @Schema(description = "JWT access token", example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...") String accessToken,

        @Schema(description = "JWT refresh token", example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...") String refreshToken,

        @Schema(description = "Type of the token, usually 'Bearer'", example = "Bearer") String tokenType,

        @Schema(description = "Expiration timestamp of the access token (UTC)", example = "2025-11-05T18:30:00Z") Instant expiresAt) {
    public AuthResponse(String accessToken, String refreshToken, Instant expiresAt) {
        this(accessToken, refreshToken, "Bearer", expiresAt);
    }
}
