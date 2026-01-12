package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.config.guard.RsaKeyProviderGuardConfig;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;

import org.springframework.context.ApplicationContext;
import org.springframework.stereotype.Component;

import java.util.Map;

/**
 * ============================================================
 * RsaKeyProviderStartupCheck
 * ============================================================
 *
 * Security bootstrap check ensuring a valid RSA key provider setup.
 *
 * <p>
 * Executed only when JWT algorithm = RSA.
 * </p>
 *
 * <p>
 * Enforces:
 * <ul>
 * <li>Exactly one RsaKeyProvider bean</li>
 * <li>Consistent rsa.source configuration</li>
 * </ul>
 *
 * <p>
 * Enforces ADR-008 (Stateless JWT Authentication).
 * </p>
 */
@Component
public final class RsaKeyProviderStartupCheck implements SecurityStartupCheck {

    private static final String CHECK_NAME = "rsa-key-provider";

    private final SecurityJwtProperties properties;
    private final ApplicationContext context;
    private final RsaKeyProviderGuardConfig guard;

    public RsaKeyProviderStartupCheck(
            SecurityJwtProperties properties,
            ApplicationContext context) {

        this.properties = properties;
        this.context = context;
        this.guard = new RsaKeyProviderGuardConfig();
    }

    @Override
    public String name() {
        return CHECK_NAME;
    }

    @Override
    public int getOrder() {
        return -90; // after JWT properties, before roles/refresh
    }

    @Override
    public void validate() {
        Map<String, RsaKeyProvider> providers = context.getBeansOfType(RsaKeyProvider.class);

        guard.validate(properties, providers);
    }
}
