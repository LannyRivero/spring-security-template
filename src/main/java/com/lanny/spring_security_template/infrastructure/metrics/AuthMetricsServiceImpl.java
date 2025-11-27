package com.lanny.spring_security_template.infrastructure.metrics;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;

/**
 * Implementation of {@link AuthMetricsService} using Micrometer for Prometheus
 * metrics exposure.
 *
 * <p>
 * Each metric is a labeled counter incremented on specific authentication or
 * authorization events.
 * </p>
 *
 * <p>
 * Exposed automatically under <code>/actuator/prometheus</code>.
 * Example PromQL queries:
 * <ul>
 * <li><code>rate(auth_login_success_total[5m])</code></li>
 * <li><code>rate(auth_token_refresh_total[5m])</code></li>
 * <li><code>auth_user_locked_total</code></li>
 * </ul>
 * </p>
 */
@Service
@Profile({ "dev", "prod" })
public class AuthMetricsServiceImpl implements AuthMetricsService {

        private final Counter loginSuccess;
        private final Counter loginFailure;
        private final Counter refresh;
        private final Counter registration;
        private final Counter bruteForce;

        // Extended metrics
        private final Counter sessionRevoked;
        private final Counter rotationFailed;
        private final Counter userLocked;
        private final Counter refreshReused;
        private final Counter passwordChange;

        public AuthMetricsServiceImpl(MeterRegistry registry) {

                this.loginSuccess = Counter.builder("auth_login_success_total")
                                .description("Number of successful logins")
                                .register(registry);

                this.loginFailure = Counter.builder("auth_login_failure_total")
                                .description("Number of failed logins")
                                .register(registry);

                this.refresh = Counter.builder("auth_token_refresh_total")
                                .description("Number of successful token refreshes")
                                .register(registry);

                this.registration = Counter.builder("auth_user_registration_total")
                                .description("Number of user registrations")
                                .register(registry);

                this.bruteForce = Counter.builder("auth_bruteforce_detected_total")
                                .description("Number of brute-force attack detections")
                                .register(registry);

                this.sessionRevoked = Counter.builder("auth_session_revoked_total")
                                .description("Number of sessions or tokens revoked")
                                .register(registry);

                this.rotationFailed = Counter.builder("auth_rotation_failed_total")
                                .description("Number of failed token rotation attempts")
                                .register(registry);

                this.userLocked = Counter.builder("auth_user_locked_total")
                                .description("Number of users temporarily locked due to failed attempts")
                                .register(registry);

                this.refreshReused = Counter.builder("auth_refresh_reused_total")
                                .description("Number of refresh tokens detected as reused")
                                .register(registry);

                this.passwordChange = Counter.builder("auth_password_change_total")
                                .description("Number of successful password changes")
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

        @Override
        public void recordSessionRevoked() {
                sessionRevoked.increment();
        }

        @Override
        public void recordRotationFailed() {
                rotationFailed.increment();
        }

        @Override
        public void recordUserLocked() {
                userLocked.increment();
        }

        @Override
        public void recordRefreshReused() {
                refreshReused.increment();
        }

        @Override
        public void recordPasswordChange() {
                passwordChange.increment();
        }
}
