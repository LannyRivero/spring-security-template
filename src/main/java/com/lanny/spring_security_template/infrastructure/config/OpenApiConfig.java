package com.lanny.spring_security_template.infrastructure.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.servers.Server;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * ✅ OpenAPI / Swagger configuration for JWT-secured REST APIs.
 * 
 * Automatically integrates the bearerAuth scheme for token-based
 * authentication.
 */
@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI springSecurityTemplateAPI() {
        return new OpenAPI()
                .info(new Info()
                        .title("Spring Security Template API")
                        .description("""
                                🔐 JWT-based authentication & authorization template for Spring Boot.

                                Provides login, refresh, and user profile endpoints with RBAC & scopes.
                                """)
                        .version("v1.0.0")
                        .license(new License()
                                .name("MIT License")
                                .url("https://opensource.org/licenses/MIT"))
                        .contact(new Contact()
                                .name("Lanny Rivero Canino")
                                .email("lanny@example.com")
                                .url("https://github.com/lanny")))
                .servers(List.of(
                        new Server().url("http://localhost:8080").description("Local Dev Server"),
                        new Server().url("https://api.example.com").description("Production Server")))
                // --- Global security requirement ---
                .addSecurityItem(new SecurityRequirement().addList("bearerAuth"))
                // --- Define the JWT bearer scheme ---
                .components(new io.swagger.v3.oas.models.Components()
                        .addSecuritySchemes("bearerAuth",
                                new SecurityScheme()
                                        .type(SecurityScheme.Type.HTTP)
                                        .scheme("bearer")
                                        .bearerFormat("JWT")
                                        .name("Authorization")
                                        .description("""
                                                Provide the JWT access token.
                                                Example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
                                                """)));
    }
}
