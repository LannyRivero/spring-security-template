package com.lanny.spring_security_template.auth.dto;

import java.time.Instant;

public record JwtResponse(
        String accessToken,
        String refreshToken,
        Instant expiresAt) {
}