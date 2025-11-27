package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.event.SecurityEvent;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import lombok.RequiredArgsConstructor;

import java.time.Instant;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Main orchestrator for user login.
 *
 * <p>
 * This service coordinates the complete authentication flow:
 * <ul>
 * <li>Verifies lockout policy (prevents brute-force attacks)</li>
 * <li>Validates user credentials and account status</li>
 * <li>Issues access/refresh tokens via {@link TokenSessionCreator}</li>
 * <li>Records metrics and resets counters after successful login</li>
 * </ul>
 * </p>
 *
 * <p>
 * Integration with {@link LoginAttemptPolicy} allows tracking and limiting
 * consecutive failed login attempts per user. When the threshold is reached,
 * the user is temporarily locked, complying with OWASP ASVS 2.3.2.
 * </p>
 *
 * <p>
 * On successful authentication:
 * <ul>
 * <li>The attempt counter is reset.</li>
 * <li>Metrics for successful logins are recorded.</li>
 * </ul>
 * On failure:
 * <ul>
 * <li>The failed attempt is recorded.</li>
 * <li>Brute-force metrics are incremented.</li>
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
     * Performs the login flow:
     * <ol>
     * <li>Checks if the user is temporarily locked.</li>
     * <li>Validates credentials.</li>
     * <li>Issues tokens if authentication succeeds.</li>
     * <li>Updates metrics and lockout counters accordingly.</li>
     * </ol>
     *
     * @param cmd {@link LoginCommand} containing username and password
     * @return {@link JwtResult} with access and refresh tokens
     * @throws UserLockedException         if user is under temporary lockout
     * @throws InvalidCredentialsException if credentials are invalid
     * @throws UsernameNotFoundException   if user does not exist
     */
    public JwtResult login(LoginCommand cmd) {
        String username = cmd.username();
        Instant now = clockProvider.now();

        if (loginAttemptPolicy.isUserLocked(username)) {
            metrics.recordFailure();
            log.warn("[AUTH_LOCK] User '{}' attempted login while locked", username);

            auditEventPublisher.publishAuthEvent(
                SecurityEvent.USER_LOCKED.name(),
                 username, 
                 now, 
                 "User attempted login while locked due to excessive failed attempts");
            throw new UserLockedException(username);
        }

        try {
            var user = validator.validate(cmd);

            JwtResult result = tokenCreator.create(user.username().value());
            metrics.recordSuccess();

            loginAttemptPolicy.resetAttempts(username);

            log.info("[AUTH_SUCCESS] User '{}' logged in successfully", username);
            auditEventPublisher.publishAuthEvent(
                SecurityEvent.LOGIN_SUCCESS.name(), 
                username, 
                now, 
                "Successful authentication and token issuance");

            return result;

        } catch (InvalidCredentialsException | UsernameNotFoundException e) {
            loginAttemptPolicy.recordFailedAttempt(username);
            metrics.recordFailure();
            log.warn("[AUTH_FAIL] Invalid credentials for user '{}': {}", username, e.getMessage());

            auditEventPublisher.publishAuthEvent(
                SecurityEvent.LOGIN_FAILURE.name(), 
                username, 
                now,
                 e.getMessage()
                 );
            
            throw e;
        } finally {
            MDC.clear();
        }
    }
}
