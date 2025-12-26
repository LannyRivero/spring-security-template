package com.lanny.spring_security_template.infrastructure.web.user.dto;

import com.lanny.spring_security_template.domain.model.User;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

/**
 * Response DTO representing a system user with their roles and scopes.
 * <p>
 * This DTO is returned by user management endpoints and includes
 * essential user information for administrative operations.
 * <p>
 * Security: Password hash is NEVER included in responses.
 */
@Schema(
        description = "User information response containing profile data, status, and authorization details",
        example = """
                {
                  "id": "550e8400-e29b-41d4-a716-446655440000",
                  "username": "john.doe",
                  "email": "john.doe@example.com",
                  "status": "ACTIVE",
                  "roles": ["ROLE_USER"],
                  "scopes": ["SCOPE_users:read", "SCOPE_profile:write"]
                }
                """
)
public record UserResponse(
        @Schema(
                description = "Unique user identifier (UUID format)",
                example = "550e8400-e29b-41d4-a716-446655440000",
                format = "uuid"
        )
        String id,

        @Schema(
                description = "Username (alphanumeric with dots, underscores, hyphens)",
                example = "john.doe",
                minLength = 3,
                maxLength = 50
        )
        String username,

        @Schema(
                description = "User email address (verified format)",
                example = "john.doe@example.com",
                format = "email"
        )
        String email,

        @Schema(
                description = "Account status: ACTIVE (normal), LOCKED (suspended), DISABLED (inactive), DELETED (soft-deleted)",
                example = "ACTIVE",
                allowableValues = {"ACTIVE", "LOCKED", "DISABLED", "DELETED"}
        )
        String status,

        @Schema(
                description = "List of assigned roles (e.g., ROLE_USER, ROLE_ADMIN). Roles determine high-level permissions.",
                example = "[\"ROLE_USER\", \"ROLE_PREMIUM\"]"
        )
        List<String> roles,

        @Schema(
                description = "List of granted scopes (e.g., SCOPE_users:read, SCOPE_profile:write). Scopes define fine-grained permissions.",
                example = "[\"SCOPE_users:read\", \"SCOPE_profile:write\", \"SCOPE_notifications:read\"]"
        )
        List<String> scopes
) {

    /**
     * Factory method to create UserResponse from domain User aggregate.
     *
     * @param user domain User aggregate
     * @return UserResponse DTO
     */
    public static UserResponse fromDomain(User user) {
        return new UserResponse(
                user.id().value().toString(),
                user.username().value(),
                user.email().value(),
                user.status().name(),
                user.roles().stream().map(role -> role.name()).toList(),
                user.scopes().stream().map(scope -> scope.name()).toList()
        );
    }
}
