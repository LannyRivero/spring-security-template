package com.lanny.spring_security_template.infrastructure.config;

import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

/**
 * Minimal OpenAPI for production environments.
 *
 * Prevents leaking internal security details or architecture metadata.
 */
@Configuration
@Profile("prod")
public class OpenApiProdConfig {

    @Bean
    public OpenAPI openAPIProd() {
        return new OpenAPI()
                .info(new io.swagger.v3.oas.models.info.Info()
                        .title("Spring Security Template API")
                        .version("1.0.0"));
    }
}
