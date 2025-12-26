package com.lanny.spring_security_template.infrastructure.web.profile.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;

/**
 * Request DTO for updating the current user's profile.
 * <p>
 * Users can update their own email through self-service operations.
 * Username changes are not allowed to maintain referential integrity.
 */
@Schema(
        description = "Request to update the current user's profile (self-service)",
        example = """
                {
                  "email": "newemail@example.com"
                }
                """
)
public record UpdateProfileRequest(
        @Schema(
                description = """
                        New email address for the user. Must be a valid email format.
                        If the email is already in use by another user, the update will be rejected.
                        """,
                example = "newemail@example.com",
                format = "email"
        )
        @Email(message = "Email must be a valid format")
        @Size(max = 100, message = "Email cannot exceed 100 characters")
        String email
) {
}
