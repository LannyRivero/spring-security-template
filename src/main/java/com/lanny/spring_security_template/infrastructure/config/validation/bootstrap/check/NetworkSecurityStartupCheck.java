package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import com.lanny.spring_security_template.infrastructure.config.guard.NetworkSecurityProdGuard;
import com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.SecurityStartupCheck;
import com.lanny.spring_security_template.infrastructure.security.network.NetworkSecurityProperties;

import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Set;

/**
 * ============================================================
 * NetworkSecurityStartupCheck
 * ============================================================
 *
 * Security bootstrap check validating network security configuration
 * for production environments.
 */
@Component
public final class NetworkSecurityStartupCheck implements SecurityStartupCheck {

    private static final String CHECK_NAME = "network";
    private static final Set<String> PROD_PROFILES = Set.of("prod");

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
        return -50; // last hard security check
    }

    @Override
    public void validate() {

        if (!isProductionProfileActive()) {
            return;
        }

        guard.validate(properties);
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
