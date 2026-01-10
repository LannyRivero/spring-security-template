package com.lanny.spring_security_template.infrastructure.security.bootstrap;

import java.util.Comparator;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.SmartLifecycle;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

/**
 * Executes all {@link SecurityStartupCheck} validations during bootstrap.
 *
 * <p>
 * This is the single entry point for security startup validation.
 * It guarantees deterministic ordering and fail-fast behavior.
 *
 * <p>
 * Security guarantee:
 * - No secrets/tokens are logged.
 * - Only check names are logged.
 */
@Component
public final class SecurityBootstrapValidator implements SmartLifecycle {

    private static final Logger log = LoggerFactory.getLogger(SecurityBootstrapValidator.class);

    private final List<SecurityStartupCheck> checks;
    private volatile boolean running = false;

    public SecurityBootstrapValidator(List<SecurityStartupCheck> checks) {
        this.checks = checks;
    }

    @Override
    public void start() {
        // Ensures it's run once as part of lifecycle start.
        if (running)
            return;

        checks.stream()
                .sorted(Comparator.comparingInt(SecurityStartupCheck::getOrder))
                .forEach(check -> {
                    log.info("Security bootstrap check: {}", check.name());
                    check.validate(); // must throw on failure
                });

        running = true;
        log.info("Security bootstrap validation completed successfully (checks={}).", checks.size());
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
     * Start early in lifecycle. This is defensive, but not too early (still after
     * bean creation).
     */
    @Override
    public int getPhase() {
        return Integer.MIN_VALUE + 100;
    }

    /**
     * We want to block startup until validation is done.
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
