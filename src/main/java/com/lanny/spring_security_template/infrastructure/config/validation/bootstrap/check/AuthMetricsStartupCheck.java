package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap.check;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsServiceNoOp;

/**
 * =====================================================================
 * AuthMetricsStartupCheck
 * =====================================================================
 *
 * Security bootstrap check enforcing mandatory authentication metrics
 * in production environments.
 *
 * <p>
 * In enterprise-grade systems, authentication and authorization flows
 * MUST be observable in production. Running without metrics makes it
 * impossible to:
 * </p>
 * <ul>
 * <li>Detect brute-force or credential stuffing attacks</li>
 * <li>Monitor authentication success/failure rates</li>
 * <li>Perform incident response and forensic analysis</li>
 * <li>Meet compliance and audit requirements</li>
 * </ul>
 *
 * <p>
 * This startup check guarantees that a real {@link AuthMetricsService}
 * implementation is configured when running under the {@code prod} profile.
 * </p>
 *
 * <p>
 * If a {@link AuthMetricsServiceNoOp} implementation is detected in
 * production, application startup is aborted immediately (fail-fast).
 * There are no fallbacks or silent degradations in production.
 * </p>
 *
 * <h2>Design principles</h2>
 * <ul>
 * <li><b>Fail-fast</b>: insecure or incomplete observability blocks
 * startup</li>
 * <li><b>Single enforcement mechanism</b>: integrated into the unified
 * {@link SecurityStartupCheck} bootstrap pipeline</li>
 * <li><b>Infrastructure-only</b>: no coupling with domain or application
 * logic</li>
 * <li><b>Explicit production guarantees</b>: observability is
 * non-negotiable</li>
 * </ul>
 *
 * <h2>Why a StartupCheck (and not a @Configuration guard)</h2>
 * <ul>
 * <li>Avoids unconditional bean instantiation failures</li>
 * <li>Ensures deterministic execution order with other security checks</li>
 * <li>Allows consistent metrics and diagnostics for bootstrap failures</li>
 * <li>Keeps all security invariants enforced in a single mechanism</li>
 * </ul>
 *
 * <h2>Profiles</h2>
 * <ul>
 * <li><b>prod</b> → enforced (startup fails if metrics are missing)</li>
 * <li>non-prod → not executed (No-Op metrics allowed)</li>
 * </ul>
 */
@Component
@Profile("prod")
public final class AuthMetricsStartupCheck implements SecurityStartupCheck {

    private static final String SOURCE = "auth-metrics";

    private final AuthMetricsService metrics;

    public AuthMetricsStartupCheck(AuthMetricsService metrics) {
        this.metrics = metrics;
    }

    @Override
    public String name() {
        return SOURCE;
    }

    /**
     * Validates that authentication metrics are properly configured
     * for production environments.
     *
     * @throws InvalidSecurityConfigurationException if a No-Op metrics
     *                                               implementation is detected in
     *                                               production
     */
    @Override
    public void validate() {

        if (metrics instanceof AuthMetricsServiceNoOp) {
            throw new InvalidSecurityConfigurationException(
                    SOURCE,
                    "Authentication metrics are disabled in production. " +
                            "Configure a real AuthMetricsService implementation " +
                            "(e.g. Micrometer/Prometheus, Kafka audit pipeline, etc.).");
        }
    }
}
