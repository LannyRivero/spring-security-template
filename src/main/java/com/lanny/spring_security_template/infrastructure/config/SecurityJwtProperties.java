package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

import java.time.Duration;
import java.util.List;

@ConfigurationProperties(prefix = "security.jwt")
public record SecurityJwtProperties(
        @DefaultValue("spring-security-template") String issuer,
        @DefaultValue("access") String accessAudience,
        @DefaultValue("refresh") String refreshAudience,
        @DefaultValue("PT15M") Duration accessTtl, // ISO-8601: 15m
        @DefaultValue("P7D") Duration refreshTtl, // 7d
        @DefaultValue("RSA") String algorithm, // RSA | HMAC (futuro)
        @DefaultValue("false") boolean rotateRefresh,
        @DefaultValue( {
        }) List<String> defaultRoles, // opcional
        @DefaultValue({}) List<String> defaultScopes // opcional
    ){
}
