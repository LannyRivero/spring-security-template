package com.lanny.spring_security_template.infrastructure.config.guard;

import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;
import com.lanny.spring_security_template.infrastructure.security.network.NetworkSecurityProperties;

/**
 * =====================================================================
 * NetworkSecurityProdGuard
 * =====================================================================
 *
 * Stateless guard enforcing correct network security configuration
 * for production environments.
 *
 * <p>
 * Prevents insecure client IP resolution when running behind proxies.
 * </p>
 */
public final class NetworkSecurityProdGuard {

    public void validate(NetworkSecurityProperties props) {

        if (props.trustedProxyPrefixes() == null
                || props.trustedProxyPrefixes().isEmpty()) {

            throw new InvalidSecurityConfigurationException(
                    "network-security",
                    "No trusted proxy prefixes configured. " +
                            "Configure 'security.network.trusted-proxy-prefixes' for production.");
        }
    }
}
