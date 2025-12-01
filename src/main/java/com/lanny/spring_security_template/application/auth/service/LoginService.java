package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.exception.UserNotFoundException;

import lombok.RequiredArgsConstructor;

/**
 * Pure application service for handling login logic.
 *
 * No logging, no MDC, no auditing.
 * Cross-cutting concerns handled by AuthUseCaseLoggingDecorator.
 */
@RequiredArgsConstructor
public class LoginService {

    private final AuthenticationValidator validator;
    private final TokenSessionCreator tokenCreator;
    private final LoginMetricsRecorder metrics;
    private final LoginAttemptPolicy loginAttemptPolicy;

    public JwtResult login(LoginCommand cmd) {
        String username = cmd.username();

        // 1. Check if user is locked
        if (loginAttemptPolicy.isUserLocked(username)) {
            metrics.recordFailure(username, "User locked");
            throw new UserLockedException(username);
        }

        try {
            // 2. Validate credentials
            var user = validator.validate(cmd);

            // 3. Issue tokens
            JwtResult result = tokenCreator.create(user.username().value());

            // 4. Reset failed attempts counter
            loginAttemptPolicy.resetAttempts(username);

            // 5. Register metrics
            metrics.recordSuccess(username);

            return result;

        } catch (InvalidCredentialsException | UserNotFoundException e) {
            // Increment failed attempts
            loginAttemptPolicy.recordFailedAttempt(username);

            // Metrics only (no logs or audit)
            metrics.recordFailure(username, e.getMessage());

            throw e;
        }
    }
}

