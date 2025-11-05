package com.lanny.spring_security_template.auth.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record RefreshRequest(
        @NotBlank
        @Pattern(regexp = "^[A-Za-z0-9\\-_.]+$", message = "Invalid refresh token format")
        String refreshToken) {
}