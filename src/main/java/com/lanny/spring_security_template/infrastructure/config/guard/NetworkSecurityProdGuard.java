package com.lanny.spring_security_template.infrastructure.config.guard;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.lanny.spring_security_template.infrastructure.security.network.NetworkSecurityProperties;

/**
 * {@code NetworkSecurityProdGuard}
 *
 * <p>
 * Production guard that enforces correct network security configuration
 * at application startup.
 * </p>
 *
 * <h2>Why this guard exists</h2>
 * <ul>
 * <li>Client IP resolution is security-critical</li>
 * <li>{@code X-Forwarded-For} headers can be spoofed</li>
 * <li>Trusted proxy configuration MUST be explicit in production</li>
 * </ul>
 *
 * <p>
 * If no trusted proxies are configured, the application will fail fast
 * during startup instead of running with insecure defaults.
 * </p>
 *
 * <h2>Applies to</h2>
 * <ul>
 * <li><b>prod</b> profile only</li>
 * </ul>
 */
@Configuration
@Profile("prod")
public class NetworkSecurityProdGuard {

    /**
     * Ensures that trusted proxy prefixes are configured in production.
     *
     * @param props network security properties
     */
    @Bean
    void ensureTrustedProxiesConfigured(NetworkSecurityProperties props) {

        if (props.trustedProxyPrefixes() == null
                || props.trustedProxyPrefixes().isEmpty()) {

            throw new IllegalStateException(
                    "SECURITY MISCONFIGURATION: " +
                            "No trusted proxy prefixes configured for production. " +
                            "Configure 'security.network.trusted-proxy-prefixes'.");
        }
    }
}
