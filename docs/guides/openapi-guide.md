# 📘 OpenAPI Documentation Guide

Complete guide to using and extending the OpenAPI documentation in this Spring Security template.

---

## Table of Contents

1. [Accessing OpenAPI UI](#accessing-openapi-ui)
2. [Authentication in Swagger UI](#authentication-in-swagger-ui)
3. [Understanding the API Structure](#understanding-the-api-structure)
4. [Error Response Format](#error-response-format)
5. [Extending Documentation](#extending-documentation)
6. [Best Practices](#best-practices)
7. [OpenAPI Configuration](#openapi-configuration)

---

## Accessing OpenAPI UI

### Swagger UI URL

The Swagger UI is available at:

```
http://localhost:8080/swagger-ui/index.html
```

**Alternative URLs**:
- `http://localhost:8080/swagger-ui.html` (redirects to above)
- `http://localhost:8080/v3/api-docs` (raw OpenAPI JSON spec)
- `http://localhost:8080/v3/api-docs.yaml` (raw OpenAPI YAML spec)

### Environment Availability

OpenAPI documentation is **only available** in:
- ✅ `dev` profile
- ✅ `local` profile
- ✅ `demo` profile
- ✅ `test` profile

❌ **Disabled in production** for security reasons (prevents API structure leakage).

---

## Authentication in Swagger UI

### Step-by-Step Authentication

#### 1. **Login to Get Token**

First, authenticate using the `/api/v1/auth/login` endpoint:

1. Find the **Authentication** section in Swagger UI
2. Expand `POST /api/v1/auth/login`
3. Click **"Try it out"**
4. Enter credentials:
   ```json
   {
     "usernameOrEmail": "admin",
     "password": "admin123"
   }
   ```
5. Click **"Execute"**
6. **Copy the `accessToken`** from the response

**Example Response**:
```json
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiIsInJvbGVzIjpbIlJPTEVfQURNSU4iXSwic2NvcGVzIjpbInVzZXI6cmVhZCIsInVzZXI6d3JpdGUiLCJ1c2VyOm1hbmFnZSIsInByb2ZpbGU6cmVhZCIsInByb2ZpbGU6d3JpdGUiXSwiaWF0IjoxNzAzNTc3NjAwLCJleHAiOjE3MDM1Nzg1MDB9...",
  "refreshToken": "...",
  "tokenType": "Bearer",
  "expiresAt": "2025-12-26T19:15:00Z"
}
```

#### 2. **Authorize Swagger UI**

1. Click the **"Authorize" 🔒 button** at the top right of Swagger UI
2. In the "bearerAuth" dialog, paste your **access token** (without "Bearer " prefix)
3. Click **"Authorize"**
4. Click **"Close"**

**Visual Indicator**: The 🔒 icon will turn into a 🔓 (unlocked) icon, indicating you're authenticated.

#### 3. **Make Authenticated Requests**

All subsequent requests will automatically include the JWT token:
```
Authorization: Bearer <your_access_token>
```

You can now test protected endpoints like:
- `GET /api/v1/auth/me` (requires authentication)
- `GET /api/v1/users` (requires `user:read` scope)

---

### Pre-Seeded Test Users

For development, these users are pre-seeded in the database:

| Username | Password | Role | Scopes |
|----------|----------|------|--------|
| `admin` | `admin123` | ROLE_ADMIN | `user:read`, `user:write`, `user:delete`, `user:manage`, `profile:read`, `profile:write` |
| `user` | `user123` | ROLE_USER | `profile:read`, `profile:write` |

**Example Test Flow**:
```bash
# 1. Login as admin
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"usernameOrEmail": "admin", "password": "admin123"}'

# 2. Use access token for protected requests
curl -X GET http://localhost:8080/api/v1/auth/me \
  -H "Authorization: Bearer <access_token>"
```

---

## Understanding the API Structure

### API Versioning

All endpoints are versioned:
```
/api/v1/auth/*    - Authentication endpoints
/api/v1/users/*   - User management (future)
/api/v1/profile/* - Profile management (future)
```

### Security Model

#### Scopes

Endpoints are protected by **scopes** (not just roles):

| Scope | Description | Required For |
|-------|-------------|--------------|
| `profile:read` | View user profiles | GET /api/v1/auth/me |
| `profile:write` | Update user profiles | PUT /api/v1/profile |
| `user:read` | View users | GET /api/v1/users |
| `user:write` | Create/update users | POST /api/v1/users |
| `user:delete` | Delete users | DELETE /api/v1/users/{id} |
| `user:manage` | Full user management | All user operations |

#### Roles → Scopes Mapping

Roles contain scopes:

**ROLE_ADMIN**:
- `user:read`
- `user:write`
- `user:delete`
- `user:manage`
- `profile:read`
- `profile:write`

**ROLE_USER**:
- `profile:read`
- `profile:write`

**Token Structure**:
```json
{
  "sub": "admin",
  "roles": ["ROLE_ADMIN"],
  "scopes": ["user:read", "user:write", "user:manage", "profile:read", "profile:write"],
  "iat": 1703577600,
  "exp": 1703578500
}
```

---

## Error Response Format

All errors follow **RFC 9457 Problem Details** standard:

### Standard Error Schema

```json
{
  "type": "about:blank",
  "title": "Unauthorized",
  "status": 401,
  "detail": "Invalid or expired JWT token",
  "instance": "/api/v1/users",
  "timestamp": "2025-12-26T18:30:00Z",
  "errors": {
    "token": "Token signature verification failed"
  }
}
```

### Common HTTP Status Codes

| Status | Title | When It Occurs |
|--------|-------|----------------|
| 400 | Bad Request | Validation errors, invalid input |
| 401 | Unauthorized | Missing/invalid/expired token |
| 403 | Forbidden | Valid token but insufficient permissions (scope) |
| 404 | Not Found | Resource doesn't exist |
| 409 | Conflict | Duplicate resource (e.g., username taken) |
| 500 | Internal Server Error | Unexpected server error |

### Validation Errors (400)

Validation errors include field-specific details:

```json
{
  "type": "about:blank",
  "title": "Bad Request",
  "status": 400,
  "detail": "Validation failed for one or more fields. Check the 'errors' field for details.",
  "instance": "/api/v1/auth/register",
  "timestamp": "2025-12-26T18:30:00Z",
  "errors": {
    "username": "Username must be between 3 and 50 characters",
    "email": "Email must be a valid email address"
  }
}
```

---

## Extending Documentation

### Adding a New Endpoint

When creating a new endpoint, follow this pattern:

```java
@RestController
@RequestMapping("/api/v1/users")
@Tag(
    name = "User Management",
    description = "Endpoints for managing users (admin only)"
)
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @Operation(
        summary = "Get all users",
        description = """
            Retrieves a paginated list of all users in the system.
            
            ## Required Scope
            - `user:read` - Read user information
            
            ## Example Usage
            ```bash
            curl -X GET http://localhost:8080/api/v1/users?page=0&size=20 \\
              -H "Authorization: Bearer <token>"
            ```
            """,
        security = @SecurityRequirement(name = "bearerAuth"),
        parameters = {
            @Parameter(
                name = "page",
                description = "Page number (zero-based)",
                example = "0",
                schema = @Schema(type = "integer", defaultValue = "0")
            ),
            @Parameter(
                name = "size",
                description = "Page size",
                example = "20",
                schema = @Schema(type = "integer", defaultValue = "20")
            )
        },
        responses = {
            @ApiResponse(
                responseCode = "200",
                description = "Users retrieved successfully",
                content = @Content(
                    mediaType = "application/json",
                    schema = @Schema(implementation = PagedUserResponse.class),
                    examples = @ExampleObject(
                        name = "Success Response",
                        value = """
                            {
                              "content": [
                                {
                                  "id": "550e8400-e29b-41d4-a716-446655440000",
                                  "username": "john.doe",
                                  "email": "john.doe@example.com",
                                  "roles": ["ROLE_USER"]
                                }
                              ],
                              "totalElements": 100,
                              "totalPages": 5,
                              "size": 20,
                              "number": 0
                            }
                            """
                    )
                )
            ),
            @ApiResponse(
                responseCode = "403",
                description = "Insufficient permissions (missing user:read scope)",
                content = @Content(
                    mediaType = "application/json",
                    examples = @ExampleObject(
                        name = "Forbidden",
                        value = """
                            {
                              "type": "about:blank",
                              "title": "Forbidden",
                              "status": 403,
                              "detail": "Insufficient permissions. Required scope: user:read",
                              "instance": "/api/v1/users"
                            }
                            """
                    )
                )
            )
        }
    )
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_user:read')")
    public ResponseEntity<Page<UserDto>> getAllUsers(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "20") int size
    ) {
        Page<UserDto> users = userService.findAll(PageRequest.of(page, size));
        return ResponseEntity.ok(users);
    }
}
```

### Key Documentation Elements

#### 1. **@Tag** (Controller Level)

```java
@Tag(
    name = "User Management",
    description = "Endpoints for managing users (admin only)"
)
```

Groups related endpoints in Swagger UI.

#### 2. **@Operation** (Method Level)

```java
@Operation(
    summary = "Short description (shown in list)",
    description = "Detailed description with examples and usage",
    security = @SecurityRequirement(name = "bearerAuth")
)
```

Documents individual endpoint with summary, description, and security requirements.

#### 3. **@Schema** (DTO Level)

```java
@Schema(
    name = "UserDto",
    description = "User data transfer object",
    example = "{\"id\": \"123\", \"username\": \"john.doe\"}"
)
public record UserDto(...) {}
```

Documents request/response models.

#### 4. **@Parameter** (Parameter Documentation)

```java
@Parameter(
    name = "id",
    description = "User ID (UUID)",
    example = "550e8400-e29b-41d4-a716-446655440000",
    required = true
)
@PathVariable String id
```

Documents path variables, query parameters, and headers.

#### 5. **@ApiResponse** (Response Documentation)

```java
@ApiResponse(
    responseCode = "200",
    description = "Success",
    content = @Content(
        mediaType = "application/json",
        schema = @Schema(implementation = UserDto.class),
        examples = @ExampleObject(value = "...")
    )
)
```

Documents expected responses with examples.

---

## Best Practices

### ✅ Do's

1. **Document all public endpoints**
   - Every REST endpoint should have `@Operation`
   - Include summary, description, and examples

2. **Provide realistic examples**
   ```java
   @ExampleObject(
       name = "Success Response",
       value = """
           {
             "id": "550e8400-e29b-41d4-a716-446655440000",
             "username": "john.doe"
           }
           """
   )
   ```

3. **Document error responses**
   - Always include 400, 401, 403, 500 responses
   - Use standardized ErrorResponse format

4. **Specify security requirements**
   ```java
   security = @SecurityRequirement(name = "bearerAuth")
   ```

5. **Document validation rules**
   ```java
   @Schema(
       description = "Username (3-50 chars, alphanumeric)",
       minLength = 3,
       maxLength = 50,
       pattern = "^[a-zA-Z0-9._-]+$"
   )
   ```

### ❌ Don'ts

1. **Don't expose internal implementation details**
   - Avoid mentioning database schemas
   - Don't expose exception stack traces in examples

2. **Don't use generic descriptions**
   ```java
   // ❌ BAD
   @Operation(summary = "Get user")
   
   // ✅ GOOD
   @Operation(
       summary = "Get user by ID",
       description = "Retrieves detailed user information including roles and scopes"
   )
   ```

3. **Don't forget to version APIs**
   - Always use `/api/v1/` prefix
   - Document breaking changes in new versions

4. **Don't hardcode sensitive data in examples**
   - Use placeholder tokens: `eyJhbGciOi...`
   - Use example domains: `example.com`

---

## OpenAPI Configuration

### Customizing Server URLs

In `application.yml`:

```yaml
# Development
openapi:
  server-url: http://localhost:8080

# Production (disabled)
spring:
  profiles:
    active: prod  # OpenAPI won't load
```

### Disabling OpenAPI in Production

OpenAPI is automatically disabled in production via profile exclusion:

```java
@Configuration
@Profile({ "dev", "local", "demo", "test" })  // NOT prod
public class OpenApiConfig {
    // Configuration only loads in non-prod profiles
}
```

### Adding Custom Tags

Edit `OpenApiConfig.java`:

```java
@Bean
public GroupedOpenApi userApi() {
    return GroupedOpenApi.builder()
        .group("users")
        .pathsToMatch("/api/v1/users/**")
        .build();
}

@Bean
public GroupedOpenApi authApi() {
    return GroupedOpenApi.builder()
        .group("authentication")
        .pathsToMatch("/api/v1/auth/**")
        .build();
}
```

This creates separate API documentation groups in Swagger UI.

---

## Advanced Features

### Generating Client SDKs

Use OpenAPI spec to generate client libraries:

```bash
# Download OpenAPI spec
curl http://localhost:8080/v3/api-docs -o openapi.json

# Generate TypeScript client
npx @openapitools/openapi-generator-cli generate \
  -i openapi.json \
  -g typescript-axios \
  -o ./generated-client

# Generate Java client
npx @openapitools/openapi-generator-cli generate \
  -i openapi.json \
  -g java \
  -o ./generated-client
```

### Contract Testing

Use OpenAPI spec for contract testing:

```java
@Test
void shouldMatchOpenApiSpec() {
    RestAssured
        .given()
            .spec(OpenApiValidator.from("http://localhost:8080/v3/api-docs"))
        .when()
            .get("/api/v1/auth/login")
        .then()
            .statusCode(405);  // Method Not Allowed
}
```

---

## Troubleshooting

### Swagger UI Not Loading

**Problem**: Accessing `http://localhost:8080/swagger-ui/index.html` returns 404.

**Solutions**:
1. **Check active profile**: Ensure you're not in `prod` profile
   ```bash
   # Check application logs for:
   # "The following profiles are active: dev"
   ```

2. **Verify dependency**: Ensure springdoc-openapi is in `pom.xml`:
   ```xml
   <dependency>
       <groupId>org.springdoc</groupId>
       <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
       <version>2.8.6</version>
   </dependency>
   ```

3. **Check URL**: Try alternative URLs:
   - `/swagger-ui.html`
   - `/swagger-ui/`

### Authentication Not Working in Swagger UI

**Problem**: Getting 401 Unauthorized despite entering token.

**Solutions**:
1. **Don't include "Bearer " prefix** when pasting token in Authorize dialog
   ```
   ❌ Bearer eyJhbGciOi...
   ✅ eyJhbGciOi...
   ```

2. **Check token expiration**: Access tokens expire after 15 minutes. Re-login if expired.

3. **Verify token format**: Token should be in JWT format (three base64 parts separated by dots).

### Missing Examples in Swagger UI

**Problem**: Request/response examples not showing.

**Solution**: Add `@ExampleObject` annotations:
```java
@ApiResponse(
    responseCode = "200",
    content = @Content(
        examples = @ExampleObject(value = "...")
    )
)
```

---

## References

- [OpenAPI Specification 3.0](https://spec.openapis.org/oas/v3.0.3)
- [Springdoc OpenAPI Documentation](https://springdoc.org/)
- [RFC 9457 - Problem Details for HTTP APIs](https://www.rfc-editor.org/rfc/rfc9457.html)
- [Swagger UI Documentation](https://swagger.io/tools/swagger-ui/)

---

**Last Updated**: 2025-12-26  
**Maintainer**: Development Team
