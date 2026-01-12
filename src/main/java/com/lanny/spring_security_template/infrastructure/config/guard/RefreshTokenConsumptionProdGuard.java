package com.lanny.spring_security_template.infrastructure.config.guard;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;
import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;

import java.util.Map;

/**
 * =====================================================================
 * RefreshTokenConsumptionProdGuard
 * =====================================================================
 *
 * Stateless guard that ensures an atomic {@link RefreshTokenConsumptionPort}
 * is configured for production environments.
 *
 * <p>
 * Refresh token reuse protection is mandatory in production.
 * Missing this port results in an insecure authentication system.
 * </p>
 */
public final class RefreshTokenConsumptionProdGuard {

    public void validate(Map<String, RefreshTokenConsumptionPort> ports) {

        if (ports.isEmpty()) {
            throw new InvalidSecurityConfigurationException(
                    "refresh-token-consumption",
                    "No RefreshTokenConsumptionPort configured. " +
                            "Atomic refresh token consumption is mandatory in production.");
        }
    }
}
