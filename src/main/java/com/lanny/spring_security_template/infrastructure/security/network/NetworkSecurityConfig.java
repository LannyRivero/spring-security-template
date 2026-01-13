package com.lanny.spring_security_template.infrastructure.security.network;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * ============================================================
 * NetworkSecurityConfig
 * ============================================================
 *
 * <p>
 * Security bootstrap configuration for network-related concerns.
 * </p>
 *
 * <p>
 * This configuration registers {@link NetworkSecurityProperties} as a
 * first-class security component, enabling strict and explicit definition
 * of trusted proxy CIDR ranges.
 * </p>
 *
 * <h2>Role in the security bootstrap</h2>
 * <ul>
 * <li>Provides immutable network security configuration</li>
 * <li>Feeds {@link ClientIpResolver} with trusted proxy data</li>
 * <li>Validated during startup by production guards</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Trusted proxies must be explicitly configured</li>
 * <li>Prevents IP spoofing via untrusted {@code X-Forwarded-For} headers</li>
 * <li>Ensures deterministic client IP resolution</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Stateless and side-effect free</li>
 * <li>No runtime logic or conditional behavior</li>
 * <li>Part of the security bootstrap phase</li>
 * </ul>
 *
 * @see NetworkSecurityProperties
 * @see ClientIpResolver
 * @see com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.guard.NetworkSecurityProdGuard
 */
@Configuration
@EnableConfigurationProperties(NetworkSecurityProperties.class)
public class NetworkSecurityConfig {
}
