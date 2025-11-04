package com.lanny.spring_security_template.web.dto;

/**
 * Data Transfer Object for authentication responses.
 *
 * @param accessToken  the JWT access token.
 * @param refreshToken the JWT refresh token.
 * @param tokenType    the type of the token, typically "Bearer".
 */
public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType) {
    public AuthResponse(String accessToken, String refreshToken) {
        this(accessToken, refreshToken, "Bearer");
    }
}
