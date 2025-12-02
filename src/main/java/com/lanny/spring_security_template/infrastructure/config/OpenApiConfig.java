package com.lanny.spring_security_template.infrastructure.config;

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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.List;

/**
 * OpenAPI configuration for non-production environments.
 *
 * Visible only in:
 * - dev
 * - local
 * - demo
 * - test
 *
 * In production this class MUST NOT load to avoid leaking internal details.
 */
@Configuration
@Profile({ "dev", "local", "demo", "test" })
@OpenAPIDefinition(info = @Info(title = "Spring Security Template API", version = "1.0.0", description = """
                🔐 Base template for enterprise-grade authentication.
                Includes JWT, refresh tokens, roles and scopes.
                """, contact = @Contact(name = "Lanny Rivero Canino", email = "contact@springtemplate.dev", url = "https://github.com/lannyrc")), servers = {
                @Server(url = "http://localhost:8080", description = "Local Dev Server")
}, security = { @SecurityRequirement(name = "bearerAuth") })
@SecurityScheme(name = "bearerAuth", scheme = "bearer", type = SecuritySchemeType.HTTP, in = SecuritySchemeIn.HEADER, bearerFormat = "JWT", description = "Provide your access token")
public class OpenApiConfig {

        @Bean
        public OpenAPI customOpenAPI(
                        @Value("${openapi.server-url:}") String configuredUrl,
                        @Value("${spring.profiles.active:dev}") String profile) {

                String url = configuredUrl.isBlank()
                                ? "http://localhost:8080"
                                : configuredUrl;

                OpenAPI openAPI = new OpenAPI()
                                .info(new io.swagger.v3.oas.models.info.Info()
                                                .title("Spring Security Template API")
                                                .version("1.0.0")
                                                .description("Developer environment – JWT Auth Template")
                                                .license(new License().name("MIT")
                                                                .url("https://opensource.org/licenses/MIT")));

                openAPI.setServers(List.of(
                                new io.swagger.v3.oas.models.servers.Server()
                                                .url(url)
                                                .description("Environment: " + profile)));

                return openAPI;
        }
}
