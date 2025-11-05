package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Request body for login operation.
 */
@Schema(name = "AuthRequest", description = "Login request with username or email and password.")
public record AuthRequest(

                @NotBlank @Schema(description = "Username or email used for authentication", example = "john.doe") String usernameOrEmail,

                @NotBlank @Schema(description = "Raw user password", example = "MySecurePass123!") String password) {
}
