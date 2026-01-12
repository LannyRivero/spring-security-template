package com.lanny.spring_security_template.infrastructure.config.validation.bootstrap;

import org.springframework.stereotype.Component;

/**
 * Default no-op implementation to avoid conditional logic
 * during security bootstrap.
 */
@Component
class NoOpSecurityBootstrapMetrics implements SecurityBootstrapMetrics {

    @Override
    public void bootstrapSucceeded(int checksCount) {
        // intentionally empty
    }

    @Override
    public void bootstrapFailed(String checkName) {
        // intentionally empty
    }
}
