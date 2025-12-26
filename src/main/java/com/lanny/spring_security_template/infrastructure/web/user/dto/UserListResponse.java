package com.lanny.spring_security_template.infrastructure.web.user.dto;

import io.swagger.v3.oas.annotations.media.Schema;

import java.util.List;

/**
 * Paginated response for user list endpoints.
 * <p>
 * Includes pagination metadata to support efficient data retrieval
 * and client-side pagination controls.
 */
@Schema(
        description = "Paginated list of users with metadata for navigation",
        example = """
                {
                  "users": [
                    {
                      "id": "550e8400-e29b-41d4-a716-446655440000",
                      "username": "admin",
                      "email": "admin@example.com",
                      "status": "ACTIVE",
                      "roles": ["ROLE_ADMIN"],
                      "scopes": ["SCOPE_users:read", "SCOPE_users:write"]
                    }
                  ],
                  "page": 0,
                  "size": 20,
                  "totalElements": 42,
                  "totalPages": 3
                }
                """
)
public record UserListResponse(
        @Schema(description = "List of users in the current page")
        List<UserResponse> users,

        @Schema(description = "Current page number (zero-indexed)", example = "0")
        int page,

        @Schema(description = "Number of items per page", example = "20")
        int size,

        @Schema(description = "Total number of users across all pages", example = "42")
        long totalElements,

        @Schema(description = "Total number of pages available", example = "3")
        int totalPages
) {
}
