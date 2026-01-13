package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.guard;

import java.util.Map;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;
import com.lanny.spring_security_template.infrastructure.adapter.security.NoOpRefreshTokenConsumptionAdapter;
import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;

/**
 * =====================================================================
 * RefreshTokenConsumptionProdGuard
 * =====================================================================
 *
 * Stateless production guard ensuring a secure, atomic refresh token
 * consumption mechanism is configured.
 *
 * <p>
 * Refresh token reuse protection is mandatory in production environments.
 * Missing or insecure consumption allows replay attacks and persistent
 * unauthorized access.
 * </p>
 *
 * <p>
 * Security guarantees:
 * </p>
 * <ul>
 * <li>Exactly one {@link RefreshTokenConsumptionPort} must be configured</li>
 * <li>No-op or development-only implementations are forbidden</li>
 * <li>Consumption must be atomic and replay-safe</li>
 * </ul>
 *
 * <p>
 * If validation fails, application startup is aborted immediately.
 * There are no fallbacks or relaxed defaults in production.
 * </p>
 */
public final class RefreshTokenConsumptionProdGuard {

    private static final String SOURCE = "refresh-token-consumption";

    public void validate(Map<String, RefreshTokenConsumptionPort> ports) {

        if (ports == null || ports.isEmpty()) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "No RefreshTokenConsumptionPort configured. " +
                            "Atomic refresh token consumption is mandatory in production.");
        }

        if (ports.size() != 1) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "Multiple RefreshTokenConsumptionPort implementations detected. " +
                            "Exactly one production-grade consumer must be configured.");
        }

        RefreshTokenConsumptionPort consumer = ports.values().iterator().next();

        if (consumer instanceof NoOpRefreshTokenConsumptionAdapter) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "NoOpRefreshTokenConsumptionAdapter is not allowed in production. " +
                            "Configure a production-grade, atomic refresh token consumer.");
        }
    }
}
