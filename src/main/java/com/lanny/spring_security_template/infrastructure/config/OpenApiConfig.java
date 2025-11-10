package com.lanny.spring_security_template.infrastructure.config;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.License;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

/**
 * OpenAPI configuration for JWT-secured Spring Boot applications.
 *
 * Provides global metadata (title, version, contact),
 * defines bearerAuth scheme for Swagger UI,
 * and registers environment-aware servers dynamically.
 */
@Configuration
@OpenAPIDefinition(info = @Info(title = "Spring Security Template API", version = "1.0.0", description = """
                🔐 Plantilla base para autenticación y autorización JWT.
                Incluye login, refresh, scopes y roles RBAC/ABAC.
                """, contact = @Contact(name = "Lanny Rivero Canino", email = "contact@springtemplate.dev", url = "https://github.com/lannyrc")), servers = {
                @Server(url = "http://localhost:8080", description = "Local Dev Server"),
                @Server(url = "https://api.springtemplate.dev", description = "Production Server")
}, security = { @SecurityRequirement(name = "bearerAuth") })
@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT", in = SecuritySchemeIn.HEADER, description = """
                Provide your JWT access token.
                Example: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
                """)
public class OpenApiConfig {

        /**
         * Creates an OpenAPI instance with license and dynamic server URL based on
         * the active Spring profile.
         */
        @Bean
        public OpenAPI customOpenAPI(@Value("${spring.profiles.active:dev}") String profile) {

                // Determinar la URL del servidor según el perfil activo
                String serverUrl;
                switch (profile) {
                        case "prod" -> serverUrl = "https://api.springtemplate.dev";
                        case "test" -> serverUrl = "http://localhost:8081";
                        default -> serverUrl = "http://localhost:8080";
                }

                // Construir el objeto OpenAPI
                OpenAPI openAPI = new OpenAPI()
                                .info(new io.swagger.v3.oas.models.info.Info()
                                                .title("Spring Security Template API")
                                                .version("1.0.0")
                                                .description("""
                                                                Template base para autenticación JWT con Spring Boot 3.x.
                                                                Incluye control de roles, scopes, refresh tokens y filtros de seguridad.
                                                                """)
                                                .license(new License()
                                                                .name("MIT License")
                                                                .url("https://opensource.org/licenses/MIT")));

                // Añadir el servidor dinámico
                io.swagger.v3.oas.models.servers.Server dynamicServer = new io.swagger.v3.oas.models.servers.Server()
                                .url(serverUrl)
                                .description(profile.toUpperCase() + " environment");

                openAPI.setServers(List.of(dynamicServer));
                return openAPI;
        }
}
