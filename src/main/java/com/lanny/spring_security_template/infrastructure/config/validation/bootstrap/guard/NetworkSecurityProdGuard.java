package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.guard;

import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;
import com.lanny.spring_security_template.infrastructure.security.network.NetworkSecurityProperties;

/**
 * =====================================================================
 * NetworkSecurityProdGuard
 * =====================================================================
 *
 * Stateless production guard enforcing strict network security configuration.
 *
 * <p>
 * This guard prevents insecure client IP resolution when the application
 * is deployed behind proxies or load balancers.
 * </p>
 *
 * <p>
 * Security rationale:
 * </p>
 * <ul>
 * <li>Without trusted proxy prefixes, client IPs can be spoofed</li>
 * <li>IP spoofing compromises rate limiting, auditing and logging</li>
 * <li>Production deployments must explicitly define trusted proxies</li>
 * </ul>
 *
 * <p>
 * If validation fails, application startup is aborted immediately.
 * There are no fallbacks or relaxed defaults in production.
 * </p>
 */
public final class NetworkSecurityProdGuard {

    private static final String SOURCE = "network-security";

    public void validate(NetworkSecurityProperties props) {

        if (props == null) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "Network security properties are missing. " +
                            "Production requires explicit network security configuration.");
        }

        if (props.trustedProxyCidrs() == null
                || props.trustedProxyCidrs().isEmpty()) {

            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "No trusted proxy CIDRs configured. " +
                            "Configure 'security.network.trusted-proxy-prefixes' for production.");
        }

        boolean hasValidCidrs = props.trustedProxyCidrs().stream()
                .anyMatch(cidr -> cidr != null && !cidr.isBlank());

        if (!hasValidCidrs) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "Trusted proxy CIDRs are empty or invalid. " +
                            "At least one non-blank proxy CIDR must be configured for production.");
        }
    }
}
