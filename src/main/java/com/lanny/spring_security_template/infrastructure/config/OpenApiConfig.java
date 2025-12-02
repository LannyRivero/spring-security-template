package com.lanny.spring_security_template.infrastructure.config;

import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;
import io.swagger.v3.oas.annotations.servers.Server;
import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.License;

/**
 * OpenAPI configuration for JWT-secured applications.
 *
 * Provides:
 * - Global OpenAPI metadata (title, version, contact).
 * - Swagger UI bearerAuth scheme.
 * - Dynamic server definition based on environment configuration.
 *
 * Notes for enterprise deployments:
 * Many production systems run behind reverse proxies or API gateways,
 * so the public URL of the API may differ from the internal service URL.
 * For that reason the server URL is also configurable via property:
 *
 * openapi.server-url=https://api.mycompany.com
 */
@Configuration
@OpenAPIDefinition(info = @Info(title = "Spring Security Template API", version = "1.0.0", description = """
                🔐 Plantilla base para autenticación y autorización JWT.
                Incluye login, refresh, scopes y roles RBAC/ABAC.
                """, contact = @Contact(name = "Lanny Rivero Canino", email = "contact@springtemplate.dev", url = "https://github.com/lannyrc")), servers = {
                @Server(url = "http://localhost:8080", description = "Local Dev Server")
}, security = { @SecurityRequirement(name = "bearerAuth") })
@SecurityScheme(name = "bearerAuth", type = SecuritySchemeType.HTTP, scheme = "bearer", bearerFormat = "JWT", in = SecuritySchemeIn.HEADER, description = "Provide your JWT access token.")
public class OpenApiConfig {

        /**
         * Builds the OpenAPI instance with optional dynamic server URL.
         *
         * @param configuredUrl external URL configured via "openapi.server-url"
         * @param profile       active spring profile (used as fallback)
         */
        @Bean
        public OpenAPI customOpenAPI(
                        @Value("${openapi.server-url:}") String configuredUrl,
                        @Value("${spring.profiles.active:dev}") String profile) {

                String finalUrl;

                if (!configuredUrl.isBlank()) {
                        // If defined, use external URL (ideal for reverse proxies)
                        finalUrl = configuredUrl;
                } else {
                        // Fallback profile-based behavior
                        finalUrl = switch (profile) {
                                case "prod" -> "https://api.springtemplate.dev";
                                case "test" -> "http://localhost:8081";
                                default -> "http://localhost:8080";
                        };
                }

                OpenAPI openAPI = new OpenAPI()
                                .info(new io.swagger.v3.oas.models.info.Info()
                                                .title("Spring Security Template API")
                                                .version("1.0.0")
                                                .description("""
                                                                Template base para autenticación JWT con Spring Boot 3.x.
                                                                Incluye control de roles, scopes, refresh tokens y filtros de seguridad.
                                                                """)
                                                .license(new License().name("MIT")
                                                                .url("https://opensource.org/licenses/MIT")));

                io.swagger.v3.oas.models.servers.Server dynamicServer = new io.swagger.v3.oas.models.servers.Server()
                                .url(finalUrl)
                                .description("Environment: " + profile.toUpperCase());

                openAPI.setServers(List.of(dynamicServer));
                return openAPI;
        }
}
