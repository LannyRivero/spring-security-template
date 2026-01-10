package com.lanny.spring_security_template.infrastructure.config.guard;

import com.lanny.spring_security_template.infrastructure.config.JwtAlgorithm;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;

import java.util.Map;

/**
 * =====================================================================
 * RsaKeyProviderGuard
 * =====================================================================
 *
 * Stateless, fail-fast guard ensuring that exactly ONE {@link RsaKeyProvider}
 * is registered when JWT algorithm = RSA.
 *
 * <p>
 * This guard enforces RSA signing/verification integrity and prevents
 * ambiguous or missing key provider configurations.
 * </p>
 *
 * <p>
 * Any violation results in {@link InvalidSecurityConfigurationException}.
 * </p>
 */
public final class RsaKeyProviderGuardConfig {

    public void validate(
            SecurityJwtProperties props,
            Map<String, RsaKeyProvider> providers) {

        if (props.algorithm() != JwtAlgorithm.RSA) {
            return;
        }

        if (props.rsa() == null || props.rsa().source() == null) {
            throw new InvalidSecurityConfigurationException("""
                    JWT algorithm is RSA but rsa.source is not configured.
                    Expected property:
                      security.jwt.rsa.source = filesystem | keystore | classpath
                    """);
        }

        if (providers.isEmpty()) {
            throw new InvalidSecurityConfigurationException("""
                    JWT algorithm is RSA but no RsaKeyProvider bean was found.
                    Expected exactly ONE provider.
                    """);
        }

        if (providers.size() > 1) {
            throw new InvalidSecurityConfigurationException("""
                    Multiple RsaKeyProvider beans detected.
                    Exactly ONE provider must be active.
                    Providers found: %s
                    """.formatted(providers.keySet()));
        }
    }
}
