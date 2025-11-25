package com.lanny.spring_security_template.infrastructure.metrics;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;

@Service
@Profile({ "dev", "prod" })
public class AuthMetricsServiceImpl implements AuthMetricsService {

    private final Counter loginSuccess;
    private final Counter loginFailure;
    private final Counter refresh;
    private final Counter registration;
    private final Counter bruteForce;

    public AuthMetricsServiceImpl(MeterRegistry registry) {
        this.loginSuccess = Counter.builder("auth_login_success_total")
                .description("Number of successful logins")
                .register(registry);

        this.loginFailure = Counter.builder("auth_login_failure_total")
                .description("Number of failed logins")
                .register(registry);

        this.refresh = Counter.builder("auth_token_refresh_total")
                .description("Number of refresh operations")
                .register(registry);

        this.registration = Counter.builder("auth_user_registration_total")
                .description("Number of user registrations")
                .register(registry);

        this.bruteForce = Counter.builder("auth_bruteforce_detected_total")
                .description("Detected brute-force patterns")
                .register(registry);
    }

    @Override
    public void recordLoginSuccess() {
        loginSuccess.increment();
    }

    @Override
    public void recordLoginFailure() {
        loginFailure.increment();
    }

    @Override
    public void recordTokenRefresh() {
        refresh.increment();
    }

    @Override
    public void recordUserRegistration() {
        registration.increment();
    }

    @Override
    public void recordBruteForceDetected() {
        bruteForce.increment();
    }
}
