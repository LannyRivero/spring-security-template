package com.lanny.spring_security_template.infrastructure.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.info.License;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.media.Content;
import io.swagger.v3.oas.models.media.MediaType;
import io.swagger.v3.oas.models.media.Schema;
import io.swagger.v3.oas.models.responses.ApiResponse;
import io.swagger.v3.oas.models.responses.ApiResponses;

import org.springdoc.core.customizers.OpenApiCustomizer;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.List;

/**
 * Enterprise-grade OpenAPI 3.0 configuration for non-production environments.
 *
 * <p>Features:
 * <ul>
 *   <li>JWT Bearer authentication with scope-based authorization</li>
 *   <li>Standardized error responses (RFC 9457 Problem Details)</li>
 *   <li>Request/Response examples for all endpoints</li>
 *   <li>Detailed API documentation with scopes</li>
 *   <li>Environment-specific server URLs</li>
 * </ul>
 *
 * <p>Visible only in:
 * <ul>
 *   <li>dev</li>
 *   <li>local</li>
 *   <li>demo</li>
 *   <li>test</li>
 * </ul>
 *
 * <p>In production this class MUST NOT load to avoid leaking internal details.
 *
 * @see <a href="https://spec.openapis.org/oas/v3.0.3">OpenAPI Specification 3.0.3</a>
 */
@Configuration
@Profile({ "dev", "local", "demo", "test" })
@OpenAPIDefinition(
    info = @Info(
        title = "Spring Security Template API",
        version = "1.0.0",
        description = """
            Enterprise-grade Spring Boot security template with JWT authentication and scope-based authorization.
            
            ## Features
            - **JWT Authentication**: Stateless authentication with access and refresh tokens
            - **Scope-Based Authorization**: Fine-grained permissions (resource:action pattern)
            - **Hybrid RBAC+ABAC**: Role-based access control with attribute-based scopes
            - **Refresh Token Rotation**: Secure token refresh with reuse detection (planned)
            - **Redis Blacklist**: Distributed token revocation
            - **Hexagonal Architecture**: Clean separation of concerns
            
            ## Security
            All protected endpoints require a valid JWT access token in the `Authorization` header:
            ```
            Authorization: Bearer <access_token>
            ```
            
            ## Scopes
            Available scopes in this template:
            - `profile:read` - View user profiles
            - `profile:write` - Update user profiles
            - `user:read` - View users (admin)
            - `user:write` - Create/update users (admin)
            - `user:delete` - Delete users (admin)
            - `user:manage` - Full user management (admin)
            
            ## Getting Started
            1. **Register** a new user (dev mode only): `POST /api/v1/auth/register`
            2. **Login** to get tokens: `POST /api/v1/auth/login`
            3. **Access protected resources** with the access token
            4. **Refresh** when token expires: `POST /api/v1/auth/refresh`
            
            ## Error Responses
            All errors follow RFC 9457 Problem Details format:
            ```json
            {
              "type": "about:blank",
              "title": "Unauthorized",
              "status": 401,
              "detail": "Invalid or expired JWT token",
              "instance": "/api/v1/users"
            }
            ```
            """,
        contact = @Contact(
            name = "Lanny Rivero Canino",
            email = "lanny@example.com",
            url = "https://github.com/LannyRivero/spring-security-template"
        ),
        license = @License(
            name = "MIT License",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    servers = {
        @Server(url = "http://localhost:8080", description = "Local Development"),
        @Server(url = "https://dev.example.com", description = "Development Environment"),
        @Server(url = "https://demo.example.com", description = "Demo Environment")
    },
    security = @SecurityRequirement(name = "bearerAuth")
)
@SecurityScheme(
    name = "bearerAuth",
    type = SecuritySchemeType.HTTP,
    scheme = "bearer",
    bearerFormat = "JWT",
    in = SecuritySchemeIn.HEADER,
    description = """
        JWT Bearer token authentication.
        
        ## How to use:
        1. Login via `/api/v1/auth/login` to get an access token
        2. Copy the `accessToken` from the response
        3. Click the "Authorize" button (🔒) above
        4. Enter: `<your_access_token>` (without "Bearer " prefix)
        5. Click "Authorize" and close the dialog
        
        All subsequent requests will include the JWT token automatically.
        
        ## Token Format:
        ```
        Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...
        ```
        
        ## Token Claims:
        - `sub`: Username
        - `roles`: List of roles (e.g., ["ROLE_ADMIN"])
        - `scopes`: List of scopes (e.g., ["user:read", "profile:write"])
        - `iat`: Issued at timestamp
        - `exp`: Expiration timestamp
        """
)
public class OpenApiConfig {

    @Bean
    public OpenAPI customOpenAPI(
            @Value("${openapi.server-url:}") String configuredUrl,
            @Value("${spring.profiles.active:dev}") String profile
    ) {
        OpenAPI openAPI = new OpenAPI();

        // Override servers if configured
        if (configuredUrl != null && !configuredUrl.isBlank()) {
            openAPI.setServers(List.of(
                new io.swagger.v3.oas.models.servers.Server()
                    .url(configuredUrl)
                    .description("Environment: " + profile)
            ));
        }

        return openAPI;
    }

    /**
     * Customizer to add global error responses to all operations.
     */
    @Bean
    public OpenApiCustomizer globalErrorResponsesCustomizer() {
        return openApi -> openApi.getPaths().values().forEach(pathItem -> 
            pathItem.readOperations().forEach(operation -> {
                ApiResponses responses = operation.getResponses();
                
                // Add 400 Bad Request if not present
                if (!responses.containsKey("400")) {
                    responses.addApiResponse("400", createErrorResponse(
                        "Bad Request",
                        "Invalid request parameters or body. Check validation errors in the response."
                    ));
                }
                
                // Add 401 Unauthorized if not present
                if (!responses.containsKey("401")) {
                    responses.addApiResponse("401", createErrorResponse(
                        "Unauthorized",
                        "Missing or invalid authentication token."
                    ));
                }
                
                // Add 403 Forbidden if not present
                if (!responses.containsKey("403")) {
                    responses.addApiResponse("403", createErrorResponse(
                        "Forbidden",
                        "Insufficient permissions. Required scope missing from JWT token."
                    ));
                }
                
                // Add 500 Internal Server Error if not present
                if (!responses.containsKey("500")) {
                    responses.addApiResponse("500", createErrorResponse(
                        "Internal Server Error",
                        "An unexpected error occurred. Please contact support if the issue persists."
                    ));
                }
            })
        );
    }

    /**
     * Creates a standardized error response schema (RFC 9457 Problem Details).
     */
    private ApiResponse createErrorResponse(String title, String description) {
        Schema<?> errorSchema = new Schema<>()
            .type("object")
            .description("RFC 9457 Problem Details for HTTP APIs")
            .addProperty("type", new Schema<>()
                .type("string")
                .description("URI reference identifying the problem type")
                .example("about:blank"))
            .addProperty("title", new Schema<>()
                .type("string")
                .description("Short, human-readable summary")
                .example(title))
            .addProperty("status", new Schema<>()
                .type("integer")
                .description("HTTP status code")
                .example(401))
            .addProperty("detail", new Schema<>()
                .type("string")
                .description("Human-readable explanation specific to this occurrence")
                .example(description))
            .addProperty("instance", new Schema<>()
                .type("string")
                .description("URI reference identifying the specific occurrence")
                .example("/api/v1/users"))
            .addProperty("timestamp", new Schema<>()
                .type("string")
                .format("date-time")
                .description("When the error occurred (ISO-8601 UTC)")
                .example("2025-12-26T18:30:00Z"));

        Content content = new Content()
            .addMediaType("application/json", new MediaType().schema(errorSchema));

        return new ApiResponse()
            .description(description)
            .content(content);
    }
}
