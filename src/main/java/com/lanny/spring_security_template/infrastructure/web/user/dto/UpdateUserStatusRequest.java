package com.lanny.spring_security_template.infrastructure.web.user.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/**
 * Request DTO for updating user account status.
 * <p>
 * Allows administrators to lock, disable, or delete user accounts.
 * Status transitions are governed by domain rules.
 */
@Schema(
        description = "Request to update a user's account status (admin operation)",
        example = """
                {
                  "status": "LOCKED"
                }
                """
)
public record UpdateUserStatusRequest(
        @Schema(
                description = """
                        New account status for the user. Valid values:
                        - ACTIVE: Normal account (can authenticate)
                        - LOCKED: Temporarily suspended (e.g., too many login failures)
                        - DISABLED: Administratively disabled (manual intervention required)
                        - DELETED: Soft-deleted (cannot be reactivated)
                        """,
                example = "LOCKED",
                allowableValues = {"ACTIVE", "LOCKED", "DISABLED", "DELETED"},
                requiredMode = Schema.RequiredMode.REQUIRED
        )
        @NotBlank(message = "Status is required")
        @Pattern(
                regexp = "ACTIVE|LOCKED|DISABLED|DELETED",
                message = "Status must be one of: ACTIVE, LOCKED, DISABLED, DELETED"
        )
        String status
) {
}
