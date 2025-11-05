package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import jakarta.validation.constraints.NotBlank;

/**
 * Login request DTO for /auth/login endpoint.
 */
public record AuthRequest(
        @NotBlank String usernameOrEmail,
        @NotBlank String password
) {}
