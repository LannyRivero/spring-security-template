package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.infrastructure.config.guard.RoleProviderProdGuardConfig;

import org.springframework.context.ApplicationContext;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;

/**
 * ============================================================
 * RoleProviderStartupCheck
 * ============================================================
 *
 * Security bootstrap check ensuring a production-grade RoleProvider
 * implementation is configured.
 *
 * <p>
 * This check is enforced only when running in {@code prod}-like environments.
 * </p>
 */
@Component
public final class RoleProviderStartupCheck implements SecurityStartupCheck {

    private static final String CHECK_NAME = "role-provider";
    private static final Set<String> PROD_PROFILES = Set.of("prod");

    private final ApplicationContext context;
    private final Environment environment;
    private final RoleProviderProdGuardConfig guard;

    public RoleProviderStartupCheck(
            ApplicationContext context,
            Environment environment) {

        this.context = context;
        this.environment = environment;
        this.guard = new RoleProviderProdGuardConfig();
    }

    @Override
    public String name() {
        return CHECK_NAME;
    }

    @Override
    public int getOrder() {
        return -80;
    }

    @Override
    public void validate() {

        if (!isProductionProfileActive()) {
            // Explicit skip outside prod
            return;
        }

        Map<String, RoleProvider> providers = context.getBeansOfType(RoleProvider.class);

        guard.validate(providers);
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
