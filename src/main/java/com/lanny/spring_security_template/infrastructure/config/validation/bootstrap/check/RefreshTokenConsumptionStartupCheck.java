package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import java.util.Map;

import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;
import com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.guard.RefreshTokenConsumptionProdGuard;

/**
 * ============================================================
 * RefreshTokenConsumptionStartupCheck
 * ============================================================
 *
 * Security bootstrap check ensuring that refresh token consumption
 * is performed atomically and securely in production environments.
 *
 * <p>
 * This check prevents unsafe refresh token reuse and replay attacks
 * by enforcing the presence of a single, production-grade consumption
 * engine (e.g. Redis-based atomic consume).
 * </p>
 *
 * <p>
 * Security rationale:
 * </p>
 * <ul>
 *   <li>Refresh token replay must be detected and blocked</li>
 *   <li>No-op or in-memory consumers are forbidden in production</li>
 *   <li>Exactly one consumption engine must be configured</li>
 * </ul>
 *
 * <p>
 * If this check fails, application startup is aborted immediately.
 * There are no fallbacks or relaxed defaults in production.
 * </p>
 */
@Component
public final class RefreshTokenConsumptionStartupCheck implements SecurityStartupCheck {

    private static final String CHECK_NAME = "refresh-token-consumption";

    private final ApplicationContext context;
    private final Environment environment;
    private final RefreshTokenConsumptionProdGuard guard;

    public RefreshTokenConsumptionStartupCheck(
            ApplicationContext context,
            Environment environment) {

        this.context = context;
        this.environment = environment;
        this.guard = new RefreshTokenConsumptionProdGuard();
    }

    @Override
    public String name() {
        return CHECK_NAME;
    }

    @Override
    public int getOrder() {
        return -70; // after role-provider, before cors and network checks
    }

    @Override
    public void validate() {

        if (!isProductionProfileActive()) {
            return;
        }

        Map<String, RefreshTokenConsumptionPort> consumptionPorts =
                context.getBeansOfType(RefreshTokenConsumptionPort.class);

        guard.validate(consumptionPorts);
    }

    private boolean isProductionProfileActive() {
        return environment.acceptsProfiles(Profiles.of("prod"));
    }
}

