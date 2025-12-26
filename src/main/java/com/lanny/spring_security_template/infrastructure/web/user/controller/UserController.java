package com.lanny.spring_security_template.infrastructure.web.user.controller;

import com.lanny.spring_security_template.application.user.service.UserManagementService;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.infrastructure.web.common.dto.ErrorResponse;
import com.lanny.spring_security_template.infrastructure.web.user.dto.UpdateUserStatusRequest;
import com.lanny.spring_security_template.infrastructure.web.user.dto.UserListResponse;
import com.lanny.spring_security_template.infrastructure.web.user.dto.UserResponse;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.ExampleObject;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

/**
 * REST controller for user management operations (administrative endpoints).
 *
 * <p>Provides endpoints for listing, retrieving, updating, and deleting user accounts.
 * All operations require administrative scopes (SCOPE_users:read, SCOPE_users:write).
 *
 * <p>These endpoints are typically used by administrators or system operators
 * to manage user accounts, enforce policies, and maintain system security.
 *
 * <p><b>Base Path:</b> /api/v1/users
 *
 * <p><b>Required Scopes:</b>
 * <ul>
 *   <li>GET operations: SCOPE_users:read</li>
 *   <li>PUT/DELETE operations: SCOPE_users:write</li>
 * </ul>
 */
@RestController
@RequestMapping("/api/v1/users")
@Tag(
        name = "User Management",
        description = """
                Administrative endpoints for managing user accounts.
                
                These endpoints allow administrators to:
                - List all users with pagination
                - Retrieve individual user details
                - Update user account status (lock, disable, delete)
                - Soft-delete user accounts
                
                All operations require appropriate scopes (SCOPE_users:read or SCOPE_users:write).
                Only users with ROLE_ADMIN typically have these scopes assigned.
                """
)
public class UserController {

    private final UserManagementService userManagementService;

    public UserController(UserManagementService userManagementService) {
        this.userManagementService = userManagementService;
    }

    @Operation(
            summary = "List all users with pagination",
            description = """
                    Retrieves a paginated list of all user accounts in the system.
                    
                    ## Authorization
                    - **Required Scope:** `SCOPE_users:read`
                    - **Typical Roles:** ROLE_ADMIN, ROLE_SYSTEM
                    
                    ## Pagination
                    Use query parameters to control pagination:
                    - `page`: Zero-based page number (default: 0)
                    - `size`: Number of items per page (default: 20, max: 100)
                    - `sort`: Sort field and direction (e.g., `username,asc` or `email,desc`)
                    
                    ## Response
                    Returns a paginated response with:
                    - List of users in the current page
                    - Pagination metadata (page number, total pages, total elements)
                    
                    ## Use Cases
                    - Admin dashboard displaying user list
                    - User search and filtering interfaces
                    - System monitoring and reporting
                    - Bulk operations preparation
                    
                    ## Performance
                    For large user bases (>10,000 users), consider:
                    - Using smaller page sizes
                    - Implementing search/filter endpoints
                    - Caching frequently accessed pages
                    
                    ## Example Usage
                    ```bash
                    # Get first page (default)
                    curl -X GET "http://localhost:8080/api/v1/users" \\
                      -H "Authorization: Bearer YOUR_JWT_TOKEN"
                    
                    # Get second page with 50 items
                    curl -X GET "http://localhost:8080/api/v1/users?page=1&size=50" \\
                      -H "Authorization: Bearer YOUR_JWT_TOKEN"
                    
                    # Get users sorted by email (descending)
                    curl -X GET "http://localhost:8080/api/v1/users?sort=email,desc" \\
                      -H "Authorization: Bearer YOUR_JWT_TOKEN"
                    ```
                    """,
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successfully retrieved user list",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = UserListResponse.class),
                                    examples = @ExampleObject(
                                            name = "Successful user list response",
                                            value = """
                                                    {
                                                      "users": [
                                                        {
                                                          "id": "550e8400-e29b-41d4-a716-446655440000",
                                                          "username": "admin",
                                                          "email": "admin@example.com",
                                                          "status": "ACTIVE",
                                                          "roles": ["ROLE_ADMIN"],
                                                          "scopes": ["SCOPE_users:read", "SCOPE_users:write"]
                                                        },
                                                        {
                                                          "id": "660e8400-e29b-41d4-a716-446655440001",
                                                          "username": "john.doe",
                                                          "email": "john.doe@example.com",
                                                          "status": "ACTIVE",
                                                          "roles": ["ROLE_USER"],
                                                          "scopes": ["SCOPE_profile:read", "SCOPE_profile:write"]
                                                        }
                                                      ],
                                                      "page": 0,
                                                      "size": 20,
                                                      "totalElements": 42,
                                                      "totalPages": 3
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
                            description = "Forbidden - Missing required scope (SCOPE_users:read)",
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
                                                      "instance": "/api/v1/users",
                                                      "timestamp": "2025-12-26T10:30:00Z"
                                                    }
                                                    """
                                    )
                            )
                    )
            }
    )
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_users:read')")
    public ResponseEntity<UserListResponse> listUsers(
            @Parameter(description = "Page number (zero-indexed)", example = "0")
            @RequestParam(defaultValue = "0") int page,

            @Parameter(description = "Page size (max 100)", example = "20")
            @RequestParam(defaultValue = "20") int size,

            @Parameter(description = "Sort field and direction (e.g., 'username,asc')", example = "username,asc")
            @RequestParam(defaultValue = "username,asc") String sort
    ) {
        // Parse sort parameter
        String[] sortParams = sort.split(",");
        Sort.Direction direction = sortParams.length > 1 && "desc".equalsIgnoreCase(sortParams[1])
                ? Sort.Direction.DESC
                : Sort.Direction.ASC;
        String sortField = sortParams[0];

        // Create pageable
        Pageable pageable = PageRequest.of(
                Math.max(0, page),
                Math.min(100, Math.max(1, size)),
                Sort.by(direction, sortField)
        );

        // Retrieve paginated users
        Page<User> userPage = userManagementService.listUsers(pageable);

        // Convert to DTOs
        UserListResponse response = new UserListResponse(
                userPage.getContent().stream()
                        .map(UserResponse::fromDomain)
                        .toList(),
                userPage.getNumber(),
                userPage.getSize(),
                userPage.getTotalElements(),
                userPage.getTotalPages()
        );

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Get user by ID",
            description = """
                    Retrieves detailed information about a specific user by their unique identifier.
                    
                    ## Authorization
                    - **Required Scope:** `SCOPE_users:read`
                    - **Typical Roles:** ROLE_ADMIN, ROLE_SYSTEM
                    
                    ## Path Parameters
                    - `userId`: UUID of the user to retrieve
                    
                    ## Response
                    Returns complete user information including:
                    - User ID, username, email
                    - Account status (ACTIVE, LOCKED, DISABLED, DELETED)
                    - Assigned roles and scopes
                    
                    ## Error Cases
                    - **404 Not Found**: User with specified ID does not exist
                    - **403 Forbidden**: Missing SCOPE_users:read permission
                    - **401 Unauthorized**: Invalid or expired JWT token
                    
                    ## Use Cases
                    - User profile management in admin dashboard
                    - User detail view for support operations
                    - Account status verification
                    - Role and permission auditing
                    
                    ## Example Usage
                    ```bash
                    curl -X GET "http://localhost:8080/api/v1/users/550e8400-e29b-41d4-a716-446655440000" \\
                      -H "Authorization: Bearer YOUR_JWT_TOKEN"
                    ```
                    """,
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Successfully retrieved user information",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = UserResponse.class),
                                    examples = @ExampleObject(
                                            name = "User details",
                                            value = """
                                                    {
                                                      "id": "550e8400-e29b-41d4-a716-446655440000",
                                                      "username": "john.doe",
                                                      "email": "john.doe@example.com",
                                                      "status": "ACTIVE",
                                                      "roles": ["ROLE_USER", "ROLE_PREMIUM"],
                                                      "scopes": ["SCOPE_profile:read", "SCOPE_profile:write", "SCOPE_notifications:read"]
                                                    }
                                                    """
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "User not found",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class),
                                    examples = @ExampleObject(
                                            name = "User not found",
                                            value = """
                                                    {
                                                      "type": "about:blank",
                                                      "title": "Not Found",
                                                      "status": 404,
                                                      "detail": "User not found: 550e8400-e29b-41d4-a716-446655440000",
                                                      "instance": "/api/v1/users/550e8400-e29b-41d4-a716-446655440000",
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
                            description = "Forbidden - Missing required scope",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class)
                            )
                    )
            }
    )
    @GetMapping("/{userId}")
    @PreAuthorize("hasAuthority('SCOPE_users:read')")
    public ResponseEntity<UserResponse> getUserById(
            @Parameter(description = "User UUID", example = "550e8400-e29b-41d4-a716-446655440000")
            @PathVariable String userId
    ) {
        User user = userManagementService.getUserById(userId);
        UserResponse response = UserResponse.fromDomain(user);
        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Update user account status",
            description = """
                    Updates the account status of a specific user (administrative operation).
                    
                    ## Authorization
                    - **Required Scope:** `SCOPE_users:write`
                    - **Typical Roles:** ROLE_ADMIN, ROLE_SYSTEM
                    
                    ## Valid Status Transitions
                    - **ACTIVE**: Normal account, can authenticate
                    - **LOCKED**: Temporarily suspended (e.g., too many failed login attempts)
                    - **DISABLED**: Administratively disabled, requires manual reactivation
                    - **DELETED**: Soft-deleted, cannot be reactivated (data retained for auditing)
                    
                    ## Request Body
                    ```json
                    {
                      "status": "LOCKED"
                    }
                    ```
                    
                    ## Use Cases
                    - Lock account after suspicious activity
                    - Disable account for policy violations
                    - Soft-delete account for GDPR compliance (retention period)
                    - Reactivate previously locked account
                    
                    ## Security Considerations
                    - Status changes are logged for audit trails
                    - DELETED status is irreversible
                    - User will be immediately logged out after status change
                    - Existing JWT tokens remain valid until expiry
                    
                    ## Example Usage
                    ```bash
                    # Lock user account
                    curl -X PUT "http://localhost:8080/api/v1/users/550e8400-e29b-41d4-a716-446655440000/status" \\
                      -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
                      -H "Content-Type: application/json" \\
                      -d '{"status": "LOCKED"}'
                    
                    # Reactivate account
                    curl -X PUT "http://localhost:8080/api/v1/users/550e8400-e29b-41d4-a716-446655440000/status" \\
                      -H "Authorization: Bearer YOUR_JWT_TOKEN" \\
                      -H "Content-Type: application/json" \\
                      -d '{"status": "ACTIVE"}'
                    ```
                    """,
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(
                            responseCode = "200",
                            description = "Status updated successfully",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = UserResponse.class),
                                    examples = @ExampleObject(
                                            name = "User with updated status",
                                            value = """
                                                    {
                                                      "id": "550e8400-e29b-41d4-a716-446655440000",
                                                      "username": "john.doe",
                                                      "email": "john.doe@example.com",
                                                      "status": "LOCKED",
                                                      "roles": ["ROLE_USER"],
                                                      "scopes": ["SCOPE_profile:read", "SCOPE_profile:write"]
                                                    }
                                                    """
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "400",
                            description = "Invalid status value",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class),
                                    examples = @ExampleObject(
                                            name = "Invalid status",
                                            value = """
                                                    {
                                                      "type": "about:blank",
                                                      "title": "Bad Request",
                                                      "status": 400,
                                                      "detail": "Validation failed for one or more fields.",
                                                      "instance": "/api/v1/users/550e8400-e29b-41d4-a716-446655440000/status",
                                                      "timestamp": "2025-12-26T10:30:00Z",
                                                      "errors": {
                                                        "status": "Status must be one of: ACTIVE, LOCKED, DISABLED, DELETED"
                                                      }
                                                    }
                                                    """
                                    )
                            )
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "User not found",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class)
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
                            description = "Forbidden - Missing required scope (SCOPE_users:write)",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class)
                            )
                    )
            }
    )
    @PutMapping("/{userId}/status")
    @PreAuthorize("hasAuthority('SCOPE_users:write')")
    public ResponseEntity<UserResponse> updateUserStatus(
            @Parameter(description = "User UUID", example = "550e8400-e29b-41d4-a716-446655440000")
            @PathVariable String userId,

            @io.swagger.v3.oas.annotations.parameters.RequestBody(
                    description = "New status for the user",
                    required = true,
                    content = @Content(
                            mediaType = "application/json",
                            schema = @Schema(implementation = UpdateUserStatusRequest.class),
                            examples = {
                                    @ExampleObject(
                                            name = "Lock account",
                                            value = "{\"status\": \"LOCKED\"}"
                                    ),
                                    @ExampleObject(
                                            name = "Activate account",
                                            value = "{\"status\": \"ACTIVE\"}"
                                    ),
                                    @ExampleObject(
                                            name = "Disable account",
                                            value = "{\"status\": \"DISABLED\"}"
                                    ),
                                    @ExampleObject(
                                            name = "Soft-delete account",
                                            value = "{\"status\": \"DELETED\"}"
                                    )
                            }
                    )
            )
            @Valid @RequestBody UpdateUserStatusRequest request
    ) {
        UserStatus newStatus = UserStatus.valueOf(request.status());
        userManagementService.updateUserStatus(userId, newStatus);

        // Retrieve updated user
        User updatedUser = userManagementService.getUserById(userId);
        UserResponse response = UserResponse.fromDomain(updatedUser);

        return ResponseEntity.ok(response);
    }

    @Operation(
            summary = "Delete user account (soft delete)",
            description = """
                    Soft-deletes a user account by setting its status to DELETED.
                    
                    ## Authorization
                    - **Required Scope:** `SCOPE_users:write`
                    - **Typical Roles:** ROLE_ADMIN, ROLE_SYSTEM
                    
                    ## Soft Delete Behavior
                    - User data is retained in the database for audit purposes
                    - Status is set to DELETED (irreversible)
                    - User cannot authenticate or be reactivated
                    - Existing JWT tokens remain valid until expiry
                    - User ID and associated data preserved for compliance
                    
                    ## GDPR Compliance
                    For full data deletion (hard delete):
                    - Implement separate endpoint with data anonymization
                    - Schedule background job to purge after retention period
                    - Ensure cascade deletion of related entities
                    
                    ## Use Cases
                    - User requests account deletion
                    - Account cleanup for inactive users
                    - Compliance with data retention policies
                    - Security incident response
                    
                    ## Example Usage
                    ```bash
                    curl -X DELETE "http://localhost:8080/api/v1/users/550e8400-e29b-41d4-a716-446655440000" \\
                      -H "Authorization: Bearer YOUR_JWT_TOKEN"
                    ```
                    """,
            security = @SecurityRequirement(name = "bearerAuth"),
            responses = {
                    @ApiResponse(
                            responseCode = "204",
                            description = "User successfully deleted (soft delete)"
                    ),
                    @ApiResponse(
                            responseCode = "404",
                            description = "User not found",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class)
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
                            description = "Forbidden - Missing required scope (SCOPE_users:write)",
                            content = @Content(
                                    mediaType = "application/json",
                                    schema = @Schema(implementation = ErrorResponse.class)
                            )
                    )
            }
    )
    @DeleteMapping("/{userId}")
    @PreAuthorize("hasAuthority('SCOPE_users:write')")
    public ResponseEntity<Void> deleteUser(
            @Parameter(description = "User UUID to delete", example = "550e8400-e29b-41d4-a716-446655440000")
            @PathVariable String userId
    ) {
        userManagementService.deleteUser(userId);
        return ResponseEntity.noContent().build();
    }
}
