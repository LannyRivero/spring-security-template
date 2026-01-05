package com.lanny.spring_security_template.infrastructure.config.guard;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import java.util.Map;

/**
 * {@code RoleProviderProdGuardConfig}
 *
 * <p>
 * Production guard that ensures a <b>non in-memory</b> {@link RoleProvider}
 * implementation is configured when running under the {@code prod} profile.
 * </p>
 *
 * <h2>Why this guard exists</h2>
 * <p>
 * In-memory role providers are acceptable for {@code dev} and {@code demo}
 * environments, but they are <b>strictly forbidden in production</b>, as they:
 * </p>
 *
 * <ul>
 * <li>Bypass authoritative identity sources (DB / IAM / LDAP)</li>
 * <li>May introduce hardcoded roles or backdoors</li>
 * <li>Break auditability and compliance expectations</li>
 * </ul>
 *
 * <p>
 * This guard performs a fail-fast validation at application startup:
 * </p>
 *
 * <ul>
 * <li>If at least one {@link RoleProvider} bean exists</li>
 * <li>And all detected implementations are in-memory</li>
 * <li>Then the application <b>refuses to start</b></li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Implemented as an {@link ApplicationRunner} to run after context
 * initialization</li>
 * <li>Profile-scoped to {@code prod} only</li>
 * <li>Does not depend on concrete implementations, only on the port</li>
 * </ul>
 *
 * <p>
 * This pattern enforces correct security wiring and prevents
 * misconfigured production deployments.
 * </p>
 */
@Configuration
@Profile("prod")
public class RoleProviderProdGuardConfig {

    /**
     * Validates that a production-grade {@link RoleProvider} is configured.
     *
     * @param context Spring application context
     * @return application runner performing the validation
     * @throws IllegalStateException if no suitable provider is found
     */
    @Bean
    ApplicationRunner roleProviderProdGuard(ApplicationContext context) {
        return args -> {

            Map<String, RoleProvider> providers = context.getBeansOfType(RoleProvider.class);

            boolean hasProductionProvider = providers.values().stream()
                    .anyMatch(provider -> !provider.getClass()
                            .getSimpleName()
                            .contains("InMemory"));

            if (!hasProductionProvider) {
                throw new IllegalStateException(
                        "No production RoleProvider configured. " +
                                "In-memory providers are not allowed in prod.");
            }
        };
    }
}
