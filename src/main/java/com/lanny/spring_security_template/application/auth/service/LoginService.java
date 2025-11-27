package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.event.SecurityEvent;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

/**
 * Coordinates the user authentication lifecycle:
 * <ul>
 * <li>Validates user credentials and lockout policy</li>
 * <li>Issues JWT tokens upon success</li>
 * <li>Records metrics and publishes audit events</li>
 * </ul>
 *
 * <p>
 * Compliant with OWASP ASVS controls:
 * <ul>
 * <li>2.3.2 – Account lockout after repeated failures</li>
 * <li>2.10.1 – Log all authentication decisions</li>
 * <li>2.10.3 – Record sufficient context for traceability</li>
 * </ul>
 * </p>
 */
@Service
@RequiredArgsConstructor
public class LoginService {

    private static final Logger log = LoggerFactory.getLogger(LoginService.class);

    private final AuthenticationValidator validator;
    private final TokenSessionCreator tokenCreator;
    private final LoginMetricsRecorder metrics;
    private final LoginAttemptPolicy loginAttemptPolicy;
    private final AuditEventPublisher auditEventPublisher;
    private final ClockProvider clockProvider;

    /**
     * Executes the secure login process:
     * <ol>
     * <li>Checks if the user is locked (brute-force protection)</li>
     * <li>Validates credentials through AuthenticationValidator</li>
     * <li>Issues JWT tokens via TokenSessionCreator</li>
     * <li>Updates metrics, resets counters, and publishes audit logs</li>
     * </ol>
     *
     * @param cmd Login command containing credentials
     * @return JwtResult with access and refresh tokens
     */
    public JwtResult login(LoginCommand cmd) {
        String username = cmd.username();
        Instant now = clockProvider.now();
        String traceId = UUID.randomUUID().toString();

        MDC.put("traceId", traceId);
        MDC.put("username", username);

        try {
            // 1️ Check if user is locked due to repeated failures
            if (loginAttemptPolicy.isUserLocked(username)) {
                metrics.recordFailure(username, "User locked");
                log.warn("[AUTH_LOCK] user={} trace={} reason=locked_after_failures", username, traceId);

                auditEventPublisher.publishAuthEvent(
                        SecurityEvent.USER_LOCKED.name(),
                        username,
                        now,
                        "User attempted login while locked after multiple failed attempts");
                throw new UserLockedException(username);
            }

            // 2️ Validate credentials
            var user = validator.validate(cmd);

            // 3️ Issue tokens
            JwtResult result = tokenCreator.create(user.username().value());
            metrics.recordSuccess(username);

            // 4️ Reset failed attempts counter
            loginAttemptPolicy.resetAttempts(username);

            // 5️ Log and publish successful event
            log.info("[AUTH_SUCCESS] user={} trace={} message=Login successful", username, traceId);
            auditEventPublisher.publishAuthEvent(
                    SecurityEvent.LOGIN_SUCCESS.name(),
                    username,
                    now,
                    "Successful authentication and token issuance");

            return result;

        } catch (InvalidCredentialsException | UsernameNotFoundException e) {
            // 6️ Handle authentication failure
            loginAttemptPolicy.recordFailedAttempt(username);
            metrics.recordFailure(username, e.getMessage());
            log.warn("[AUTH_FAIL] user={} trace={} reason={}", username, traceId, e.getMessage());

            auditEventPublisher.publishAuthEvent(
                    SecurityEvent.LOGIN_FAILURE.name(),
                    username,
                    now,
                    e.getMessage());
            throw e;

        } finally {
            MDC.clear();
        }
    }
}
