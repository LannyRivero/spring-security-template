package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

/**
 * Request for creating a new user account.
 *
 * <p>This endpoint is only available in development mode for security reasons.
 * In production, user registration should go through a secure, audited process
 * with email verification, CAPTCHA, and rate limiting.
 *
 * <p>Validation Rules:
 * <ul>
 *   <li>Username: 3-50 characters, alphanumeric with dots and underscores</li>
 *   <li>Password: 6-100 characters (consider stronger requirements in production)</li>
 *   <li>Email: Valid email format</li>
 * </ul>
 */
@Schema(
    name = "RegisterRequest",
    description = "User registration payload. Only enabled in development mode (app.auth.register-enabled=true).",
    example = """
        {
          "username": "johndoe",
          "password": "SecurePass123!",
          "email": "john.doe@example.com"
        }
        """
)
public record RegisterRequest(

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 50, message = "Username must be between 3 and 50 characters")
    @Pattern(
        regexp = "^[a-zA-Z0-9._-]+$",
        message = "Username can only contain alphanumeric characters, dots, underscores, and hyphens"
    )
    @Schema(
        description = "Desired username. Must be unique, 3-50 characters, alphanumeric with dots, underscores, or hyphens.",
        example = "johndoe",
        requiredMode = Schema.RequiredMode.REQUIRED,
        minLength = 3,
        maxLength = 50,
        pattern = "^[a-zA-Z0-9._-]+$"
    )
    String username,

    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
    @Schema(
        description = "Desired password. Minimum 6 characters. Consider using a strong password with uppercase, lowercase, numbers, and symbols.",
        example = "SecurePass123!",
        requiredMode = Schema.RequiredMode.REQUIRED,
        format = "password",
        minLength = 6,
        maxLength = 100
    )
    String password,

    @NotBlank(message = "Email is required")
    @Email(message = "Email must be a valid email address")
    @Size(max = 255, message = "Email must not exceed 255 characters")
    @Schema(
        description = "User email address. Must be unique and valid format.",
        example = "john.doe@example.com",
        requiredMode = Schema.RequiredMode.REQUIRED,
        format = "email",
        maxLength = 255
    )
    String email
) {
}
