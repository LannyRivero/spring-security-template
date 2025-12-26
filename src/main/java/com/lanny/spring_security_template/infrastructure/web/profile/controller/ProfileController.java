package com.lanny.spring_security_template.infrastructure.web.profile.controller;

import com.lanny.spring_security_template.application.profile.service.ProfileService;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.infrastructure.web.common.dto.ErrorResponse;
import com.lanny.spring_security_template.infrastructure.web.profile.dto.ProfileResponse;
import com.lanny.spring_security_template.infrastructure.web.profile.dto.UpdateProfileRequest;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for user profile self-service operations.
 *
 * <p>Provides endpoints for authenticated users to view and update their own
 * profile information. Unlike {@link com.lanny.spring_security_template.infrastructure.web.user.controller.UserController},
 * these endpoints operate on the current user's own data only.
 *
 * <p><b>Base Path:</b> /api/v1/profile
 *
 * <p><b>Required Scopes:</b>
 * <ul>
 *   <li>GET operations: SCOPE_profile:read</li>
 *   <li>PUT operations: SCOPE_profile:write</li>
 * </ul>
 *
 * <p><b>Scope Assignment:</b> These scopes are typically granted to all authenticated
 * users, allowing them to manage their own profile without administrative privileges.
 */
@RestController
@RequestMapping("/api/v1/profile")
@Tag(
        name = "User Profile",
        description = """
                Self-service endpoints for authenticated users to manage their own profile.
                
                These endpoints allow users to:
                - View their current profile information
                - Update their email address
                - View their assigned roles and scopes
                
                All operations require authentication and appropriate scopes
                (SCOPE_profile:read or SCOPE_profile:write). These scopes are
                typically granted to all authenticated users.
                
                Profile operations are distinguished from user management operations:
                - Profile endpoints: Self-service, operate on current user
                - User management endpoints: Administrative, operate on any user
                """
)
public class ProfileController {

    private final ProfileService profileService;

    public ProfileController(ProfileService profileService) {
        this.profileService = profileService;
    }

    @Operation(
            summary = "Get current user's profile",
            description = """
                    Retrieves the authenticated user's profile information.
                    
                    ## Authorization
                    - **Required Scope:** `SCOPE_profile:read`
                    - **Typical Roles:** All authenticated users (ROLE_USER, ROLE_ADMIN, etc.)
                    
                    ## User Identification
                    The user is identified from the JWT token's subject claim (user ID).
                    No user ID needs to be provided in the request.
                    
                    ## Response
                    Returns complete profile information including:
                    - User ID, username, email
                    - Account status
                    - Assigned roles and scopes
                    
                    ## Use Cases
                    - Display user profile in application UI
                    - Show current user's permissions
                    - Verify account status
                    - Profile page in user dashboard
                    
                    ## Security
                    - Users can only view their own profile
                    - JWT token determines which user's data is returned
                    - No risk of unauthorized access to other users' data
                    
                    ## Example Usage
                    ```bash
                    # Get current user's profile
                    curl -X GET "http://localhost:8080/api/v1/profile" \\
                      -H "Authorization: Bearer YOUR_JWT_TOKEN"
                    ```
                    
                    ## Testing with Pre-seeded Users
                    Use the pre-seeded accounts from the /api/v1/auth/login endpoint:
                    
                    **Regular User:**
                    - Username: `user`
                    - Password: `user123`
                    - Scopes: SCOPE_profile:read, SCOPE_profile:write
                    
                    **Admin User:**
                    - Username: `admin`
                    - Password: `admin123`
                    - Scopes: All scopes including profile, users, notifications
                    """,
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successfully retrieved profile",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ProfileResponse.class),
                                    examples = @ExampleObject(
                                            name = "User profile",
                                            value = """
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
                            )
                    ),
                    @ApiResponse(
                            responseCode = "401",
                            description = "Unauthorized - Invalid or expired JWT token",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class),
                                    examples = @ExampleObject(
                                            name = "Invalid token",
                                            value = """
                                                    {
                                                      "type": "about:blank",
                                                      "title": "Unauthorized",
                                                      "status": 401,
                                                      "detail": "Invalid username/email or password",
                                                      "instance": "/api/v1/profile",
                                                      "timestamp": "2025-12-26T10:30:00Z"
                                                    }
                                                    """
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "403",
                            description = "Forbidden - Missing required scope (SCOPE_profile:read)",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class),
                                    examples = @ExampleObject(
                                            name = "Insufficient permissions",
                                            value = """
                                                    {
                                                      "type": "about:blank",
                                                      "title": "Forbidden",
                                                      "status": 403,
                                                      "detail": "Insufficient permissions. Required scope missing from JWT token.",
                                                      "instance": "/api/v1/profile",
                                                      "timestamp": "2025-12-26T10:30:00Z"
                                                    }
                                                    """
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "User not found (should not occur for authenticated users)",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class)
                            )
                    )
            }
    )
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_profile:read')")
    public ResponseEntity<ProfileResponse> getProfile(Authentication authentication) {
        String userId = extractUserId(authentication);
        User user = profileService.getProfile(userId);
        ProfileResponse response = ProfileResponse.fromDomain(user);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Update current user's profile",
            description = """
                    Updates the authenticated user's profile information.
                    
                    ## Authorization
                    - **Required Scope:** `SCOPE_profile:write`
                    - **Typical Roles:** All authenticated users
                    
                    ## Updatable Fields
                    Currently supports updating:
                    - **Email**: New email address (must be unique)
                    
                    Fields that cannot be updated via this endpoint:
                    - Username (immutable for referential integrity)
                    - Roles (requires administrative privileges)
                    - Scopes (managed by role assignments)
                    - Account status (requires administrative privileges)
                    
                    ## Request Body
                    ```json
                    {
                      "email": "newemail@example.com"
                    }
                    ```
                    
                    ## Validation Rules
                    - Email must be valid format
                    - Email must be unique (not already used by another user)
                    - Email cannot exceed 100 characters
                    
                    ## Error Cases
                    - **400 Bad Request**: Invalid email format
                    - **409 Conflict**: Email already in use by another user
                    - **403 Forbidden**: Missing SCOPE_profile:write permission
                    - **401 Unauthorized**: Invalid or expired JWT token
                    
                    ## Use Cases
                    - User changes their email address
                    - Email verification/update flow
                    - Profile completion after social login
                    
                    ## Security Considerations
                    - Email change does not require old email verification (implement if needed)
                    - No email verification sent (implement if required)
                    - JWT token remains valid after email change
                    - Consider implementing email verification workflow for production
                    
                    ## Example Usage
                    ```bash
                    # Update email address
                    curl -X PUT "http://localhost:8080/api/v1/profile" \\
                      -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
                      -H "Content-Type: application/json" \\
                      -d '{"email": "newemail@example.com"}'
                    ```
                    
                    ## Future Enhancements
                    Consider adding support for:
                    - Profile picture upload
                    - Display name / full name
                    - Phone number
                    - Timezone preference
                    - Language preference
                    - Notification preferences
                    """,
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Profile updated successfully",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ProfileResponse.class),
                                    examples = @ExampleObject(
                                            name = "Updated profile",
                                            value = """
                                                    {
                                                      "id": "550e8400-e29b-41d4-a716-446655440000",
                                                      "username": "john.doe",
                                                      "email": "newemail@example.com",
                                                      "status": "ACTIVE",
                                                      "roles": ["ROLE_USER"],
                                                      "scopes": ["SCOPE_profile:read", "SCOPE_profile:write"]
                                                    }
                                                    """
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Invalid email format",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class),
                                    examples = @ExampleObject(
                                            name = "Invalid email",
                                            value = """
                                                    {
                                                      "type": "about:blank",
                                                      "title": "Bad Request",
                                                      "status": 400,
                                                      "detail": "Validation failed for one or more fields.",
                                                      "instance": "/api/v1/profile",
                                                      "timestamp": "2025-12-26T10:30:00Z",
                                                      "errors": {
                                                        "email": "Email must be a valid format"
                                                      }
                                                    }
                                                    """
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "409",
                            description = "Email already in use by another user",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class),
                                    examples = @ExampleObject(
                                            name = "Email conflict",
                                            value = """
                                                    {
                                                      "type": "about:blank",
                                                      "title": "Conflict",
                                                      "status": 409,
                                                      "detail": "Email already in use: existing@example.com",
                                                      "instance": "/api/v1/profile",
                                                      "timestamp": "2025-12-26T10:30:00Z"
                                                    }
                                                    """
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "401",
                            description = "Unauthorized - Invalid or expired JWT token",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class)
                            )
                    ),
                    @ApiResponse(
                            responseCode = "403",
                            description = "Forbidden - Missing required scope (SCOPE_profile:write)",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class)
                            )
                    )
            }
    )
    @PutMapping
    @PreAuthorize("hasAuthority('SCOPE_profile:write')")
    public ResponseEntity<ProfileResponse> updateProfile(
            Authentication authentication,

            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "Updated profile information",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UpdateProfileRequest.class),
                            examples = {
                                    @ExampleObject(
                                            name = "Update email",
                                            value = "{\"email\": \"newemail@example.com\"}"
                                    ),
                                    @ExampleObject(
                                            name = "Update to Gmail",
                                            value = "{\"email\": \"john.doe@gmail.com\"}"
                                    ),
                                    @ExampleObject(
                                            name = "Update to corporate email",
                                            value = "{\"email\": \"john.doe@company.com\"}"
                                    )
                            }
                    )
            )
            @Valid @RequestBody UpdateProfileRequest request
    ) {
        String userId = extractUserId(authentication);

        // Update email (if provided and different from current)
        if (request.email() != null && !request.email().isBlank()) {
            profileService.updateEmail(userId, request.email());
        }

        // Retrieve updated profile
        User updatedUser = profileService.getProfile(userId);
        ProfileResponse response = ProfileResponse.fromDomain(updatedUser);

        return ResponseEntity.ok(response);
    }

    /**
     * Extracts the user ID from the JWT token.
     *
     * @param authentication Spring Security authentication object
     * @return user ID from JWT subject claim
     */
    private String extractUserId(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuth) {
            return jwtAuth.getToken().getSubject();
        }
        throw new IllegalStateException("Unable to extract user ID from authentication");
    }
}
