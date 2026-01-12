package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.guard.NetworkSecurityProdGuard;
import com.lanny.spring_security_template.infrastructure.security.network.NetworkSecurityProperties;

/**
 * ============================================================
 * NetworkSecurityStartupCheck
 * ============================================================
 *
 * Security bootstrap check validating network security configuration
 * for production environments.
 *
 * <p>
 * This check enforces non-negotiable network-level security constraints
 * before the application is allowed to start in production.
 * </p>
 *
 * <p>
 * Security rationale:
 * </p>
 * <ul>
 * <li>Prevent exposure of internal endpoints</li>
 * <li>Forbid insecure network defaults in production</li>
 * <li>Ensure explicit network hardening is configured</li>
 * </ul>
 *
 * <p>
 * If this check fails, the application startup is aborted immediately.
 * There are no fallbacks or relaxed defaults in production.
 * </p>
 */
@Component
public final class NetworkSecurityStartupCheck implements SecurityStartupCheck {

    private static final String CHECK_NAME = "network";

    private final NetworkSecurityProperties properties;
    private final Environment environment;
    private final NetworkSecurityProdGuard guard;

    public NetworkSecurityStartupCheck(
            NetworkSecurityProperties properties,
            Environment environment) {

        this.properties = properties;
        this.environment = environment;
        this.guard = new NetworkSecurityProdGuard();
    }

    @Override
    public String name() {
        return CHECK_NAME;
    }

    @Override
    public int getOrder() {
        return -50; // last hard security check before application readiness
    }

    @Override
    public void validate() {

        if (!isProductionProfileActive()) {
            return;
        }

        guard.validate(properties);
    }

    private boolean isProductionProfileActive() {
        return environment.acceptsProfiles(Profiles.of("prod"));
    }
}
