package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * ======================================================================
 * JwtConfig
 * ======================================================================
 *
 * Enables strongly-typed JWT configuration properties
 * ({@link SecurityJwtProperties}) so they can be injected safely
 * throughout the infrastructure layer.
 *
 * Architectural Role:
 * - Centralizes JWT binding from external configuration (YAML/ENV/Vault)
 * - Avoids boilerplate
 * - Keeps JWT settings out of application/domain layers
 *
 * Security Impact:
 * - Supports environment-specific JWT keys
 * - Allows TTL changes without redeploying
 * - Required for secure key rotation strategies
 */
@Configuration
@EnableConfigurationProperties(SecurityJwtProperties.class)
public class JwtConfig {
}

