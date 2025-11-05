package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import jakarta.validation.constraints.NotBlank;

public record RefreshRequest(@NotBlank String refreshToken) {
}
