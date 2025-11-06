package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.util.List;

@ConfigurationProperties(prefix = "security.cors")
public record SecurityCorsProperties(
    @DefaultValue({"http://localhost:4200","http://localhost:5173"}) List<String> allowedOrigins,
    @DefaultValue({"GET","POST","PUT","PATCH","DELETE","OPTIONS"}) List<String> allowedMethods,
    @DefaultValue({"Authorization","Content-Type","X-Correlation-Id"}) List<String> allowedHeaders,
    @DefaultValue({"X-Correlation-Id"}) List<String> exposedHeaders,
    @DefaultValue("false") boolean allowCredentials
) {}

