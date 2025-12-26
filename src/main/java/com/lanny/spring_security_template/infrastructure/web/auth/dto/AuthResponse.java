package com.lanny.spring_security_template.infrastructure.web.auth.dto;

import io.swagger.v3.oas.annotations.media.Schema;
import java.time.Instant;

/**
 * Response containing JWT tokens after successful authentication or token refresh.
 *
 * <p>This response includes both access and refresh tokens with their respective metadata.
 * The access token is used for authenticating API requests, while the refresh token is used
 * to obtain new access tokens when they expire.
 *
 * <p>Token Security:
 * <ul>
 *   <li>Access tokens are short-lived (typically 15 minutes)</li>
 *   <li>Refresh tokens are long-lived (typically 7 days)</li>
 *   <li>Store refresh tokens securely (httpOnly cookies in production)</li>
 *   <li>Never expose tokens to JavaScript in browser environments</li>
 * </ul>
 */
@Schema(
    name = "AuthResponse",
    description = "JWT authentication response containing access token, refresh token, and expiration metadata.",
    example = """
        {
          "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZSIsInJvbGVzIjpbIlJPTEVfVVNFUiJdLCJzY29wZXMiOlsicHJvZmlsZTpyZWFkIiwicHJvZmlsZTp3cml0ZSJdLCJpYXQiOjE3MDM1Nzc2MDAsImV4cCI6MTcwMzU3ODUwMH0.signature",
          "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZSIsInR5cGUiOiJyZWZyZXNoIiwiaWF0IjoxNzAzNTc3NjAwLCJleHAiOjE3MDQxODI0MDB9.signature",
          "tokenType": "Bearer",
          "expiresAt": "2025-12-26T19:15:00Z"
        }
        """
)
public record AuthResponse(

    @Schema(
        description = "JWT access token. Use this token in the Authorization header for subsequent requests: `Authorization: Bearer <token>`",
        example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZSIsInJvbGVzIjpbIlJPTEVfVVNFUiJdLCJzY29wZXMiOlsicHJvZmlsZTpyZWFkIiwicHJvZmlsZTp3cml0ZSJdLCJpYXQiOjE3MDM1Nzc2MDAsImV4cCI6MTcwMzU3ODUwMH0.signature",
        requiredMode = Schema.RequiredMode.REQUIRED
    )
    String accessToken,

    @Schema(
        description = "JWT refresh token. Use this token to obtain a new access token when it expires. Store securely (httpOnly cookie recommended).",
        example = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZSIsInR5cGUiOiJyZWZyZXNoIiwiaWF0IjoxNzAzNTc3NjAwLCJleHAiOjE3MDQxODI0MDB9.signature",
        requiredMode = Schema.RequiredMode.REQUIRED
    )
    String refreshToken,

    @Schema(
        description = "Token type for use in Authorization header. Always 'Bearer' in this implementation.",
        example = "Bearer",
        requiredMode = Schema.RequiredMode.REQUIRED,
        defaultValue = "Bearer"
    )
    String tokenType,

    @Schema(
        description = "Access token expiration timestamp in ISO-8601 UTC format. Refresh the token before this time.",
        example = "2025-12-26T19:15:00Z",
        requiredMode = Schema.RequiredMode.REQUIRED,
        type = "string",
        format = "date-time"
    )
    Instant expiresAt
) {
    /**
     * Convenience constructor that defaults tokenType to "Bearer".
     */
    public AuthResponse(String accessToken, String refreshToken, Instant expiresAt) {
        this(accessToken, refreshToken, "Bearer", expiresAt);
    }
}
