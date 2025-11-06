package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotBlank;

/**
 * Request for refreshing an access token.
 */
@Schema(name = "RefreshRequest", description = "Request containing a valid refresh token.")
public record RefreshRequest(

        @NotBlank @Schema(description = "Refresh token to renew access", example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...") String refreshToken) {
}
