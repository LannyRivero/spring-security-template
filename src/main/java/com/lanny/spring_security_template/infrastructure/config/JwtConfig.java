package com.lanny.spring_security_template.infrastructure.config;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * ======================================================================
 * JwtConfig
 * ======================================================================
 *
 * Infrastructure-level configuration responsible for enabling the
 * {@link SecurityJwtProperties} class as a Spring-bound configuration
 * properties component.
 *
 * <h2>Architectural Purpose</h2>
 * <p>
 * This configuration activates strongly-typed JWT properties, ensuring that
 * security-sensitive values (issuer, TTLs, key IDs, audiences, etc.) are
 * loaded from external configuration (YAML, environment variables, Vault).
 * </p>
 *
 * <h2>Clean Architecture Alignment</h2>
 * <p>
 * This class:
 * </p>
 * <ul>
 * <li>does not create beans other than property holders</li>
 * <li>keeps JWT settings out of the application and domain layers</li>
 * <li>acts as a composition helper for infrastructure security components</li>
 * </ul>
 *
 * <h2>Security Considerations</h2>
 * <p>
 * By externalizing JWT properties:
 * </p>
 * <ul>
 * <li>environment-based key rotation becomes possible</li>
 * <li>different TTLs or audiences may be applied per environment</li>
 * <li>secret-key and RSA paths are managed outside the codebase</li>
 * </ul>
 *
 * This makes the system compliant with OWASP ASVS 1.1 (Configuration Security).
 */
@Configuration
@EnableConfigurationProperties(SecurityJwtProperties.class)
public class JwtConfig {
}
