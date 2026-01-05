package com.lanny.spring_security_template.infrastructure.config.guard;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenConsumptionPort;

@Configuration
@Profile("prod")
public class RefreshTokenConsumptionProdGuard {

    @Bean
    RefreshTokenConsumptionPort refreshTokenConsumptionMissingGuard() {
        throw new IllegalStateException(
            "FATAL: No RefreshTokenConsumptionPort configured for prod. " +
            "Atomic refresh token consumption is mandatory."
        );
    }
}

