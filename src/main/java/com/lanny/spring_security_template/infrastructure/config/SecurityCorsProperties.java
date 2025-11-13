package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

/**
 *  Security CORS properties — configurable desde application.yml
 * 
 * Ejemplo:
 * security:
 *   cors:
 *     allowed-origins: ["http://localhost:4200","http://localhost:5173"]
 *     allowed-methods: ["GET","POST","PUT","PATCH","DELETE","OPTIONS"]
 *     allowed-headers: ["Authorization","Content-Type","X-Correlation-Id"]
 *     exposed-headers: ["X-Correlation-Id"]
 *     allow-credentials: false
 */
@ConfigurationProperties(prefix = "security.cors")
public record SecurityCorsProperties(
        @DefaultValue({"*"}) List<String> allowedOrigins,
        @DefaultValue({"GET","POST","PUT","DELETE","OPTIONS"}) List<String> allowedMethods,
        @DefaultValue({"Authorization","Content-Type"}) List<String> allowedHeaders,
        @DefaultValue({"X-Correlation-Id"}) List<String> exposedHeaders,
        @DefaultValue("false") boolean allowCredentials
) {}


