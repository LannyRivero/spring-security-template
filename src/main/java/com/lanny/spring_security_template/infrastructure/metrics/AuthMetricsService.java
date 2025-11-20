package com.lanny.spring_security_template.infrastructure.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.stereotype.Service;

@Service
public class AuthMetricsService {

    private final Counter loginSuccessCounter;
    private final Counter loginFailureCounter;
    private final Counter refreshCounter;
    private final Counter userRegistrationCounter;
    private final Counter bruteForceCounter;

    public AuthMetricsService(MeterRegistry registry) {
        this.loginSuccessCounter = Counter.builder("auth_login_success_total")
                .description("Number of successful logins")
                .register(registry);

        this.loginFailureCounter = Counter.builder("auth_login_failure_total")
                .description("Number of failed logins")
                .register(registry);

        this.refreshCounter = Counter.builder("auth_token_refresh_total")
                .description("Number of token refresh operations")
                .register(registry);

        this.userRegistrationCounter = Counter.builder("auth_user_registration_total")
                .description("Number of user registration (dev only)")
                .register(registry);

        this.bruteForceCounter = Counter.builder("auth_bruteforce_detected_total")
                .description("Number of brute-force login patterns detected(per user+IP)")
                .register(registry);
    }

    public void recordLoginSuccess() {
        loginSuccessCounter.increment();
    }

    public void recordLoginFailure() {
        loginFailureCounter.increment();
    }

    public void recordTokenRefresh() {
        refreshCounter.increment();
    }

    public void recordUserRegistration() {
        userRegistrationCounter.increment();
    }
    
    public void recordBruteForceDetected() {
        bruteForceCounter.increment();
    }
}

