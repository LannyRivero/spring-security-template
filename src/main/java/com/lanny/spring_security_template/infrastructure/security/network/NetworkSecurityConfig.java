package com.lanny.spring_security_template.infrastructure.security.network;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * =====================================================================
 * NetworkSecurityConfig
 * =====================================================================
 *
 * Network security bootstrap configuration.
 *
 * <p>
 * Registers and activates {@link NetworkSecurityProperties} as a first-class
 * configuration component of the security infrastructure.
 * </p>
 *
 * <p>
 * This configuration enables strict, explicit definition of trusted proxy
 * CIDR ranges used during client IP resolution.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Trusted proxies must be explicitly configured</li>
 * <li>Prevents IP spoofing via untrusted {@code X-Forwarded-For} headers</li>
 * <li>Ensures deterministic client IP resolution in production</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Stateless and side-effect free</li>
 * <li>Part of the security bootstrap phase</li>
 * <li>No runtime logic or conditional behavior</li>
 * </ul>
 *
 * @see NetworkSecurityProperties
 * @see ClientIpResolver
 */
@Configuration
@EnableConfigurationProperties(NetworkSecurityProperties.class)
public class NetworkSecurityConfig {
}
