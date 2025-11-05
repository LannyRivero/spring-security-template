package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import java.time.Instant;

/**
 * DTO for JWT authentication responses.
 *
 * @param accessToken  JWT token for API access
 * @param refreshToken Refresh token for renewing access
 * @param tokenType    Token type, usually "Bearer"
 * @param expiresAt    Expiration timestamp of the access token
 */
public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        Instant expiresAt
) {
    public AuthResponse(String accessToken, String refreshToken, Instant expiresAt) {
        this(accessToken, refreshToken, "Bearer", expiresAt);
    }
}

