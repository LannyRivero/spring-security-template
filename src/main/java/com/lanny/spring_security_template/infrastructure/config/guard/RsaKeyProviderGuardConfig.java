package com.lanny.spring_security_template.infrastructure.config.guard;

import com.lanny.spring_security_template.infrastructure.config.JwtAlgorithm;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import jakarta.annotation.PostConstruct;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Configuration;

import java.util.Map;

/**
 * =====================================================================
 * RsaKeyProviderGuardConfig
 * =====================================================================
 *
 * Fail-fast guard ensuring that exactly ONE {@link RsaKeyProvider}
 * is registered when JWT algorithm = RSA.
 *
 * This prevents:
 *  - zero providers (JWT signing impossible)
 *  - multiple providers (ambiguous signing/verification)
 *  - misconfigured rsa.source values
 *
 * Executed at application startup.
 */
@Configuration
public class RsaKeyProviderGuardConfig {

    private final SecurityJwtProperties props;
    private final ApplicationContext context;

    public RsaKeyProviderGuardConfig(
            SecurityJwtProperties props,
            ApplicationContext context) {

        this.props = props;
        this.context = context;
    }

    @PostConstruct
    void validate() {

        if (props.algorithm() != JwtAlgorithm.RSA) {
            return;
        }

        if (props.rsa() == null || props.rsa().source() == null) {
            throw new IllegalStateException("""
                SECURITY FATAL ERROR:
                JWT algorithm is RSA but rsa.source is not configured.

                Expected property:
                  security.jwt.rsa.source = filesystem | keystore | classpath
                """);
        }

        Map<String, RsaKeyProvider> providers =
                context.getBeansOfType(RsaKeyProvider.class);

        if (providers.isEmpty()) {
            throw new IllegalStateException("""
                SECURITY FATAL ERROR:
                JWT algorithm is RSA but no RsaKeyProvider bean was found.

                rsa.source = %s

                Expected exactly ONE provider.
                Check:
                  - security.jwt.rsa.source
                  - provider @ConditionalOnProperty
                """.formatted(props.rsa().source()));
        }

        if (providers.size() > 1) {
            throw new IllegalStateException("""
                SECURITY FATAL ERROR:
                Multiple RsaKeyProvider beans detected.

                rsa.source = %s
                Providers found: %s

                Exactly ONE provider must be active.
                """.formatted(
                    props.rsa().source(),
                    providers.keySet()
                ));
        }
    }
}


