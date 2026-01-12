package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;
import com.lanny.spring_security_template.infrastructure.config.guard.RefreshTokenConsumptionProdGuard;
import com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.SecurityStartupCheck;

import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

/**
 * ============================================================
 * RefreshTokenConsumptionStartupCheck
 * ============================================================
 *
 * Security bootstrap check ensuring atomic refresh token consumption
 * is configured for production environments.
 *
 * <p>
 * Enforced only when running under {@code prod}-like profiles.
 * </p>
 */
@Component
public final class RefreshTokenConsumptionStartupCheck implements SecurityStartupCheck {

    private static final String CHECK_NAME = "refresh-token-consumption";
    private static final Set<String> PROD_PROFILES = Set.of("prod");

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
        return -70; // after role-provider, before cors/network
    }

    @Override
    public void validate() {

        if (!isProductionProfileActive()) {
            return;
        }

        Map<String, RefreshTokenConsumptionPort> ports = context.getBeansOfType(RefreshTokenConsumptionPort.class);

        guard.validate(ports);
    }

    private boolean isProductionProfileActive() {
        for (String profile : environment.getActiveProfiles()) {
            if (PROD_PROFILES.contains(profile)) {
                return true;
            }
        }
        return false;
    }
}
