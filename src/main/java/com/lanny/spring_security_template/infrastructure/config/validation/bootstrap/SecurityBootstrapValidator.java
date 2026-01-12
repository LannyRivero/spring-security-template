package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap;

import java.util.Comparator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.config.validation.InvalidSecurityConfigurationException;

/**
 * Executes all {@link SecurityStartupCheck} validations during bootstrap.
 *
 * <p>
 * This is the single entry point for security startup validation.
 * It guarantees deterministic ordering and fail-fast behavior.
 * </p>
 *
 * <p>
 * <b>Security guarantees</b>:
 * <ul>
 * <li>Application fails fast if security configuration is invalid</li>
 * <li>No secrets, tokens or key material are logged</li>
 * <li>All validations are executed in deterministic order</li>
 * </ul>
 */
@Component
public final class SecurityBootstrapValidator implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(SecurityBootstrapValidator.class);

    private final List<SecurityStartupCheck> checks;
    private final SecurityBootstrapMetrics metrics;

    private volatile boolean running = false;

    public SecurityBootstrapValidator(
            List<SecurityStartupCheck> checks,
            SecurityBootstrapMetrics metrics) {

        this.checks = checks;
        this.metrics = metrics;
    }

    @Override
    public void start() {
        if (running) {
            return;
        }

        if (checks.isEmpty()) {
            throw new IllegalStateException(
                    "No SecurityStartupCheck beans registered — security bootstrap validation is mandatory");
        }

        try {
            checks.stream()
                    .sorted(Comparator.comparingInt(SecurityStartupCheck::getOrder))
                    .forEach(check -> {
                        log.info("Security bootstrap check [{}] starting", check.name());
                        check.validate(); // must throw on failure
                        log.info("Security bootstrap check [{}] OK", check.name());
                    });

            metrics.bootstrapSucceeded(checks.size());
            running = true;

            log.info(
                    "Security bootstrap validation completed successfully (checks={})",
                    checks.size());

        } catch (RuntimeException ex) {
            // Emit failure metric with the logical check name if possible
            if (ex instanceof InvalidSecurityConfigurationException isc) {
                metrics.bootstrapFailed(isc.getSource());
            } else {
                metrics.bootstrapFailed("unknown");
            }
            throw ex; // FAIL FAST — never swallow
        }
    }

    @Override
    public void stop() {
        running = false;
    }

    @Override
    public boolean isRunning() {
        return running;
    }

    /**
     * Start early in lifecycle. This ensures validation happens
     * before any security-sensitive component is used.
     */
    @Override
    public int getPhase() {
        return Integer.MIN_VALUE + 100;
    }

    /**
     * Block application startup until validation completes.
     */
    @Override
    public boolean isAutoStartup() {
        return true;
    }

    @Override
    public void stop(@NonNull Runnable callback) {
        stop();
        callback.run();
    }
}
