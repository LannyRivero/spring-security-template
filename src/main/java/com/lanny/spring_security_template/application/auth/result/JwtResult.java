package com.lanny.spring_security_template.application.auth.result;

import java.time.Instant;

public record JwtResult(String accessToken, String refreshToken, Instant expiresAt) {
}
