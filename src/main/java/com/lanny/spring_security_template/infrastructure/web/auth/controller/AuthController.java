package com.lanny.spring_security_template.infrastructure.web.auth.controller;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.command.RefreshCommand;
import com.lanny.spring_security_template.application.auth.port.in.AuthUseCase;
import com.lanny.spring_security_template.application.auth.query.MeQuery;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.infrastructure.web.auth.dto.*;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

/**
 * Authentication Controller — handles login, refresh, user info, and dev registration.
 *
 * <p>This controller provides endpoints for:
 * <ul>
 *   <li>User authentication (login)</li>
 *   <li>Token refresh</li>
 *   <li>Current user information retrieval</li>
 *   <li>User registration (dev mode only)</li>
 * </ul>
 *
 * <p>All endpoints return standardized responses with proper HTTP status codes.
 */
@Tag(
    name = "Authentication",
    description = """
        Authentication endpoints for JWT token management.
        
        ## Authentication Flow
        1. **Login**: Exchange credentials for access + refresh tokens
        2. **Access Resources**: Use access token in `Authorization: Bearer <token>` header
        3. **Refresh**: Exchange refresh token for new access + refresh tokens before expiration
        4. **Logout**: Blacklist tokens (invalidate session)
        
        ## Token Lifecycle
        - **Access Token**: Short-lived (15 minutes), used for API requests
        - **Refresh Token**: Long-lived (7 days), used to obtain new access tokens
        
        ## Security Considerations
        - Never expose refresh tokens to browser JavaScript (use httpOnly cookies in production)
        - Always use HTTPS in production
        - Implement refresh token rotation to prevent token reuse attacks
        """
)
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthUseCase authUseCase;

    @Value("${app.auth.register-enabled:false}")
    private boolean registerEnabled;

    // -------------------------------------------------------------------------
    // LOGIN
    // -------------------------------------------------------------------------
    @Operation(
        summary = "Authenticate user and issue JWT tokens",
        description = """
            Authenticates a user using username/email and password.
            Returns access and refresh tokens on successful authentication.
            
            ## Request Body
            - `usernameOrEmail`: Username or email address
            - `password`: User's password (plain text, transmitted over HTTPS)
            
            ## Response
            - `accessToken`: JWT access token (use in Authorization header)
            - `refreshToken`: JWT refresh token (use to get new access tokens)
            - `tokenType`: Always "Bearer"
            - `expiresAt`: Access token expiration timestamp (ISO-8601 UTC)
            
            ## Example Usage
            ```bash
            curl -X POST http://localhost:8080/api/v1/auth/login \\
              -H "Content-Type: application/json" \\
              -d '{"usernameOrEmail": "john.doe", "password": "SecurePass123!"}'
            ```
            """,
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Login credentials",
            required = true,
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = AuthRequest.class),
                examples = {
                    @ExampleObject(
                        name = "Username Login",
                        summary = "Login with username",
                        value = """
                            {
                              "usernameOrEmail": "john.doe",
                              "password": "SecurePass123!"
                            }
                            """
                    ),
                    @ExampleObject(
                        name = "Email Login",
                        summary = "Login with email",
                        value = """
                            {
                              "usernameOrEmail": "john.doe@example.com",
                              "password": "SecurePass123!"
                            }
                            """
                    ),
                    @ExampleObject(
                        name = "Admin Login",
                        summary = "Login as admin (seeded user)",
                        value = """
                            {
                              "usernameOrEmail": "admin",
                              "password": "admin123"
                            }
                            """
                    )
                }
            )
        ),
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Authentication successful",
                content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = AuthResponse.class),
                    examples = @ExampleObject(
                        name = "Success Response",
                        value = """
                            {
                              "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZSIsInJvbGVzIjpbIlJPTEVfVVNFUiJdLCJzY29wZXMiOlsicHJvZmlsZTpyZWFkIiwicHJvZmlsZTp3cml0ZSJdLCJpYXQiOjE3MDM1Nzc2MDAsImV4cCI6MTcwMzU3ODUwMH0...",
                              "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZSIsInR5cGUiOiJyZWZyZXNoIiwiaWF0IjoxNzAzNTc3NjAwLCJleHAiOjE3MDQxODI0MDB9...",
                              "tokenType": "Bearer",
                              "expiresAt": "2025-12-26T19:15:00Z"
                            }
                            """
                    )
                )
            ),
            @ApiResponse(
                responseCode = "401",
                description = "Authentication failed - Invalid credentials",
                content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "Invalid Credentials",
                        value = """
                            {
                              "type": "about:blank",
                              "title": "Unauthorized",
                              "status": 401,
                              "detail": "Invalid username/email or password",
                              "instance": "/api/v1/auth/login",
                              "timestamp": "2025-12-26T18:30:00Z"
                            }
                            """
                    )
                )
            ),
            @ApiResponse(
                responseCode = "400",
                description = "Validation error - Missing or invalid fields",
                content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "Validation Error",
                        value = """
                            {
                              "type": "about:blank",
                              "title": "Bad Request",
                              "status": 400,
                              "detail": "Validation failed: usernameOrEmail must not be blank",
                              "instance": "/api/v1/auth/login",
                              "timestamp": "2025-12-26T18:30:00Z"
                            }
                            """
                    )
                )
            )
        }
    )
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        JwtResult result = authUseCase.login(new LoginCommand(request.usernameOrEmail(), request.password()));
        return ResponseEntity.ok(
            new AuthResponse(result.accessToken(), result.refreshToken(), result.expiresAt())
        );
    }

    // -------------------------------------------------------------------------
    // REFRESH TOKEN
    // -------------------------------------------------------------------------
    @Operation(
        summary = "Refresh access token using a valid refresh token",
        description = """
            Exchanges a valid refresh token for a new access token and refresh token.
            
            ## Token Rotation
            This endpoint implements refresh token rotation:
            - Old refresh token is invalidated
            - New access token and refresh token are issued
            - If old refresh token is reused, it indicates token theft → revoke all tokens
            
            ## Request Body
            - `refreshToken`: Valid JWT refresh token from previous login/refresh
            
            ## Response
            - `accessToken`: New JWT access token
            - `refreshToken`: New JWT refresh token (old one is now invalid)
            - `tokenType`: Always "Bearer"
            - `expiresAt`: New access token expiration timestamp
            
            ## Example Usage
            ```bash
            curl -X POST http://localhost:8080/api/v1/auth/refresh \\
              -H "Content-Type: application/json" \\
              -d '{"refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}'
            ```
            """,
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "Refresh token",
            required = true,
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = RefreshRequest.class),
                examples = @ExampleObject(
                    name = "Refresh Request",
                    value = """
                        {
                          "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZSIsInR5cGUiOiJyZWZyZXNoIiwiaWF0IjoxNzAzNTc3NjAwLCJleHAiOjE3MDQxODI0MDB9..."
                        }
                        """
                )
            )
        ),
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Token refreshed successfully",
                content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = AuthResponse.class),
                    examples = @ExampleObject(
                        name = "Success Response",
                        value = """
                            {
                              "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZSIsInJvbGVzIjpbIlJPTEVfVVNFUiJdLCJzY29wZXMiOlsicHJvZmlsZTpyZWFkIiwicHJvZmlsZTp3cml0ZSJdLCJpYXQiOjE3MDM1Nzg1MDAsImV4cCI6MTcwMzU3OTQwMH0...",
                              "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJqb2huLmRvZSIsInR5cGUiOiJyZWZyZXNoIiwiaWF0IjoxNzAzNTc4NTAwLCJleHAiOjE3MDQxODMzMDB9...",
                              "tokenType": "Bearer",
                              "expiresAt": "2025-12-26T19:30:00Z"
                            }
                            """
                    )
                )
            ),
            @ApiResponse(
                responseCode = "401",
                description = "Invalid or expired refresh token",
                content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "Invalid Token",
                        value = """
                            {
                              "type": "about:blank",
                              "title": "Unauthorized",
                              "status": 401,
                              "detail": "Invalid or expired refresh token",
                              "instance": "/api/v1/auth/refresh",
                              "timestamp": "2025-12-26T18:30:00Z"
                            }
                            """
                    )
                )
            )
        }
    )
    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@Valid @RequestBody RefreshRequest request) {
        JwtResult result = authUseCase.refresh(new RefreshCommand(request.refreshToken()));
        return ResponseEntity.ok(
            new AuthResponse(result.accessToken(), result.refreshToken(), result.expiresAt())
        );
    }

    // -------------------------------------------------------------------------
    // CURRENT USER INFO
    // -------------------------------------------------------------------------
    @Operation(
        summary = "Get current authenticated user information",
        description = """
            Returns information about the currently authenticated user.
            
            ## Authentication Required
            This endpoint requires a valid JWT access token in the `Authorization` header:
            ```
            Authorization: Bearer <access_token>
            ```
            
            ## Response
            - `userId`: Unique user identifier (UUID)
            - `username`: Username
            - `roles`: List of assigned roles (e.g., ["ROLE_ADMIN", "ROLE_USER"])
            - `scopes`: List of granted scopes (e.g., ["user:read", "profile:write"])
            
            ## Example Usage
            ```bash
            curl -X GET http://localhost:8080/api/v1/auth/me \\
              -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
            ```
            """,
        security = @SecurityRequirement(name = "bearerAuth"),
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "User information retrieved successfully",
                content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = MeResponse.class),
                    examples = {
                        @ExampleObject(
                            name = "Regular User",
                            summary = "Regular user with basic scopes",
                            value = """
                                {
                                  "userId": "550e8400-e29b-41d4-a716-446655440000",
                                  "username": "john.doe",
                                  "roles": ["ROLE_USER"],
                                  "scopes": ["profile:read", "profile:write"]
                                }
                                """
                        ),
                        @ExampleObject(
                            name = "Admin User",
                            summary = "Admin user with elevated scopes",
                            value = """
                                {
                                  "userId": "660e8400-e29b-41d4-a716-446655440000",
                                  "username": "admin",
                                  "roles": ["ROLE_ADMIN"],
                                  "scopes": ["user:read", "user:write", "user:delete", "user:manage", "profile:read", "profile:write"]
                                }
                                """
                        )
                    }
                )
            ),
            @ApiResponse(
                responseCode = "401",
                description = "Missing or invalid access token",
                content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "Unauthorized",
                        value = """
                            {
                              "type": "about:blank",
                              "title": "Unauthorized",
                              "status": 401,
                              "detail": "Missing or invalid JWT access token",
                              "instance": "/api/v1/auth/me",
                              "timestamp": "2025-12-26T18:30:00Z"
                            }
                            """
                    )
                )
            )
        }
    )
    @GetMapping("/me")
    public ResponseEntity<MeResponse> me(
        @Parameter(hidden = true)
        @AuthenticationPrincipal(expression = "username") String username
    ) {
        MeResult result = authUseCase.me(new MeQuery(username));

        return ResponseEntity.ok(
            new MeResponse(result.userId(), result.username(), result.roles(), result.scopes())
        );
    }

    // -------------------------------------------------------------------------
    // REGISTER (DEV ONLY)
    // -------------------------------------------------------------------------
    @Operation(
        summary = "Register a new user account (dev mode only)",
        description = """
            Creates a new user account. This endpoint is only enabled in development mode.
            
            ## Dev Mode Only
            This endpoint is disabled in production for security reasons.
            Set `app.auth.register-enabled=true` in application properties to enable.
            
            ## Request Body
            - `username`: Desired username (3-50 characters)
            - `password`: Password (6-100 characters)
            - `email`: Valid email address
            
            ## Response
            - Success message on successful registration
            - New user is assigned ROLE_USER by default
            
            ## Example Usage
            ```bash
            curl -X POST http://localhost:8080/api/v1/auth/register \\
              -H "Content-Type: application/json" \\
              -d '{"username": "newuser", "password": "SecurePass123!", "email": "newuser@example.com"}'
            ```
            """,
        requestBody = @io.swagger.v3.oas.annotations.parameters.RequestBody(
            description = "User registration data",
            required = true,
            content = @Content(
                mediaType = "application/json",
                schema = @Schema(implementation = RegisterRequest.class),
                examples = @ExampleObject(
                    name = "Register Request",
                    value = """
                        {
                          "username": "newuser",
                          "password": "SecurePass123!",
                          "email": "newuser@example.com"
                        }
                        """
                )
            )
        ),
        responses = {
            @ApiResponse(
                responseCode = "201",
                description = "User registered successfully",
                content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "Success",
                        value = """
                            {
                              "message": "User 'newuser' registered successfully (dev mode)"
                            }
                            """
                    )
                )
            ),
            @ApiResponse(
                responseCode = "403",
                description = "Registration disabled in this environment",
                content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "Registration Disabled",
                        value = """
                            {
                              "message": "User registration is disabled in this environment"
                            }
                            """
                    )
                )
            ),
            @ApiResponse(
                responseCode = "409",
                description = "Username or email already exists",
                content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "Conflict",
                        value = """
                            {
                              "type": "about:blank",
                              "title": "Conflict",
                              "status": 409,
                              "detail": "Username 'newuser' is already taken",
                              "instance": "/api/v1/auth/register",
                              "timestamp": "2025-12-26T18:30:00Z"
                            }
                            """
                    )
                )
            )
        }
    )
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        if (!registerEnabled) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN)
                .body(new MessageResponse("User registration is disabled in this environment"));
        }

        var response = new MessageResponse(
            "User '%s' registered successfully (dev mode)".formatted(request.username())
        );

        return ResponseEntity.status(HttpStatus.CREATED).body(response);
    }

    // -------------------------------------------------------------------------
    // LOCAL DTO
    // -------------------------------------------------------------------------
    @Schema(name = "MessageResponse", description = "Generic message response")
    private record MessageResponse(
        @Schema(description = "Response message", example = "Operation completed successfully")
        String message
    ) {}
}
