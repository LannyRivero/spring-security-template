package com.lanny.spring_security_template.infrastructure.config.guard;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;

import java.util.Map;

/**
 * =====================================================================
 * RoleProviderProdGuard
 * =====================================================================
 *
 * Stateless guard that ensures a production-grade {@link RoleProvider}
 * is configured when running in production-like environments.
 *
 * <p>
 * In-memory role providers are strictly forbidden in production.
 * </p>
 */
public final class RoleProviderProdGuardConfig {

    public void validate(Map<String, RoleProvider> providers) {

        if (providers.isEmpty()) {
            throw new InvalidSecurityConfigurationException(
                    "No RoleProvider bean configured. At least one production provider is required.");
        }

        boolean hasProductionProvider = providers.values().stream()
                .anyMatch(provider -> !provider.getClass()
                        .getSimpleName()
                        .contains("InMemory"));

        if (!hasProductionProvider) {
            throw new InvalidSecurityConfigurationException(
                    "Only in-memory RoleProvider implementations detected. " +
                            "In-memory providers are not allowed in production.");
        }
    }
}
