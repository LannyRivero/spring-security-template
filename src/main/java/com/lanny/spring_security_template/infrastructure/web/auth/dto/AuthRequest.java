package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Request body for user authentication (login).
 *
 * <p>This DTO accepts either a username or email address along with the user's password.
 * Both fields are required and must not be blank.
 */
@Schema(
    name = "AuthRequest",
    description = "Authentication request payload for login operation. Accepts username or email with password.",
    example = "{\"usernameOrEmail\": \"john.doe\", \"password\": \"SecurePass123!\"}"
)
public record AuthRequest(

    @NotBlank(message = "Username or email is required")
    @Size(min = 3, max = 100, message = "Username or email must be between 3 and 100 characters")
    @Schema(
        description = "Username or email address for authentication. Case-insensitive for email.",
        example = "john.doe",
        requiredMode = Schema.RequiredMode.REQUIRED,
        minLength = 3,
        maxLength = 100
    )
    String usernameOrEmail,

    @NotBlank(message = "Password is required")
    @Size(min = 6, max = 100, message = "Password must be between 6 and 100 characters")
    @Schema(
        description = "User's password (plain text). Always use HTTPS in production to protect credentials.",
        example = "SecurePass123!",
        requiredMode = Schema.RequiredMode.REQUIRED,
        format = "password",
        minLength = 6,
        maxLength = 100
    )
    String password
) {
}
