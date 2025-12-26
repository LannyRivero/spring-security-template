package com.lanny.spring_security_template.infrastructure.web.profile.dto;

import com.lanny.spring_security_template.domain.model.User;
import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

/**
 * Response DTO for the current user's profile information.
 * <p>
 * Similar to UserResponse but focused on self-service profile operations.
 * Users can view and update their own profile through these endpoints.
 */
@Schema(
        description = "Current user's profile information (self-service)",
        example = """
                {
                  "id": "550e8400-e29b-41d4-a716-446655440000",
                  "username": "john.doe",
                  "email": "john.doe@example.com",
                  "status": "ACTIVE",
                  "roles": ["ROLE_USER"],
                  "scopes": ["SCOPE_profile:read", "SCOPE_profile:write"]
                }
                """
)
public record ProfileResponse(
        @Schema(
                description = "User's unique identifier",
                example = "550e8400-e29b-41d4-a716-446655440000"
        )
        String id,

        @Schema(
                description = "User's username",
                example = "john.doe"
        )
        String username,

        @Schema(
                description = "User's email address",
                example = "john.doe@example.com"
        )
        String email,

        @Schema(
                description = "Account status",
                example = "ACTIVE"
        )
        String status,

        @Schema(
                description = "Assigned roles",
                example = "[\"ROLE_USER\"]"
        )
        List<String> roles,

        @Schema(
                description = "Granted scopes (permissions)",
                example = "[\"SCOPE_profile:read\", \"SCOPE_profile:write\"]"
        )
        List<String> scopes
) {

    /**
     * Factory method to create ProfileResponse from domain User aggregate.
     *
     * @param user domain User aggregate
     * @return ProfileResponse DTO
     */
    public static ProfileResponse fromDomain(User user) {
        return new ProfileResponse(
                user.id().value().toString(),
                user.username().value(),
                user.email().value(),
                user.status().name(),
                user.roles().stream().map(role -> role.name()).toList(),
                user.scopes().stream().map(scope -> scope.name()).toList()
        );
    }
}
