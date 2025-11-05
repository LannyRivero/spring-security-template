package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.util.List;

/**
 * Response for /auth/me endpoint.
 */
@Schema(name = "MeResponse", description = "Details of the authenticated user.")
public record MeResponse(

        @Schema(description = "User ID", example = "b1f29c6d-7c77-4b42-b17e-3b5d9a113c8b") String userId,

        @Schema(description = "Username of the authenticated user", example = "johndoe") String username,

        @Schema(description = "Assigned roles", example = "[\"USER\", \"ADMIN\"]") List<String> roles,

        @Schema(description = "Granted scopes", example = "[\"profile:read\", \"profile:write\"]") List<String> scopes) {
}
