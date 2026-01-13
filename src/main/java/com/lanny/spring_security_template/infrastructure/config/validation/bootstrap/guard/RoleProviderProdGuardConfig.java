package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.guard;

import java.util.Map;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;
import com.lanny.spring_security_template.infrastructure.security.provider.InMemoryRoleProvider;

/**
 * =====================================================================
 * RoleProviderProdGuard
 * =====================================================================
 *
 * Stateless production guard enforcing a production-grade RoleProvider
 * configuration.
 *
 * <p>
 * Role resolution is a critical authorization component. In production,
 * role data MUST originate from a controlled, persistent source.
 * </p>
 *
 * <p>
 * Security guarantees:
 * </p>
 * <ul>
 * <li>At least one {@link RoleProvider} must be configured</li>
 * <li>In-memory or development-only providers are forbidden</li>
 * <li>Authorization behavior must be deterministic and auditable</li>
 * </ul>
 *
 * <p>
 * Any violation aborts application startup immediately.
 * There are no fallbacks in production.
 * </p>
 */
public final class RoleProviderProdGuardConfig {

    private static final String SOURCE = "role-provider";

    public void validate(Map<String, RoleProvider> providers) {

        if (providers == null || providers.isEmpty()) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "No RoleProvider configured. A production-grade RoleProvider is required.");
        }

        if (providers.size() > 1) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "Multiple RoleProvider implementations detected. " +
                            "Exactly one production-grade RoleProvider must be configured.");
        }

        RoleProvider provider = providers.values().iterator().next();

        if (provider instanceof InMemoryRoleProvider) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "InMemoryRoleProvider is not allowed in production. " +
                            "Configure a persistent, production-grade RoleProvider.");
        }
    }
}
