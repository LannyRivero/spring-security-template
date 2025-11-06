package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request for creating a new user account (dev mode).
 */
@Schema(name = "RegisterRequest", description = "User registration payload (enabled only in dev profile).")
public record RegisterRequest(

        @NotBlank @Size(min = 3, max = 50) @Schema(description = "Desired username", example = "johndoe") String username,

        @NotBlank @Size(min = 6, max = 100) @Schema(description = "Desired password", example = "MySecurePass123!") String password,

        @NotBlank @Email @Schema(description = "User email address", example = "john.doe@example.com") String email) {
}
