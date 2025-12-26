package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptPolicy;
import com.lanny.spring_security_template.application.auth.policy.LoginAttemptResult;
import com.lanny.spring_security_template.application.auth.result.JwtResult;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.exception.UserNotFoundException;

import lombok.RequiredArgsConstructor;

/**
 * Core application service responsible for executing the login use case.
 *
 * <p>
 * This component encapsulates all domain-driven authentication rules:
 * </p>
 *
 * <ul>
 * <li>User lockout enforcement via {@link LoginAttemptPolicy}</li>
 * <li>Credential validation through {@link AuthenticationValidator}</li>
 * <li>Token issuance using {@link TokenSessionCreator}</li>
 * <li>Login success/failure metrics through {@link LoginMetricsRecorder}</li>
 * </ul>
 *
 * <p>
 * This service contains <strong>zero</strong> cross-cutting concerns:
 * no logging, no auditing, no MDC, no Spring annotations.
 * Those concerns are implemented in {@code AuthUseCaseLoggingDecorator}
 * and infrastructure adapters, keeping the application layer pure and testable.
 * </p>
 *
 * <h2>Flow summary</h2>
 * <ol>
 * <li>Reject request if the user is temporarily locked</li>
 * <li>Validate credentials (username/password)</li>
 * <li>Create a new authenticated session and issue JWT tokens</li>
 * <li>Reset failed login attempts on success</li>
 * <li>Record success/failure metrics</li>
 * </ol>
 *
 * <h2>Error semantics</h2>
 * <ul>
 * <li>{@link UserLockedException}: user exceeded allowed failed attempts</li>
 * <li>{@link InvalidCredentialsException}: password mismatch or invalid
 * input</li>
 * <li>{@link UserNotFoundException}: invalid username/email</li>
 * </ul>
 *
 * <p>
 * Designed for Clean Architecture and high observability through decorators.
 * </p>
 */
@RequiredArgsConstructor
public class LoginService {

    private final AuthenticationValidator validator;
    private final TokenSessionCreator tokenCreator;
    private final LoginMetricsRecorder metrics;
    private final LoginAttemptPolicy loginAttemptPolicy;

    /**
     * Executes the login use case:
     * <ul>
     * <li>Validates user credentials</li>
     * <li>Issues access/refresh tokens</li>
     * <li>Updates login attempt counters</li>
     * <li>Records login metrics</li>
     * </ul>
     *
     * @param cmd the login request payload (username + raw password)
     * @return a {@link JwtResult} containing access and refresh tokens
     *
     * @throws UserLockedException         if the user is temporarily locked by
     *                                     policy
     * @throws InvalidCredentialsException if credentials are incorrect
     * @throws UserNotFoundException       if the user does not exist
     */
    public JwtResult login(LoginCommand cmd) {
        String username = cmd.username();

        try {
            // Validate credentials (pure domain rule)
            var user = validator.validate(cmd);

            // Successful login → reset policy state
            loginAttemptPolicy.resetAttempts(username);

            // Issue tokens
            JwtResult result = tokenCreator.create(user.username().value());

            // Record success
            metrics.recordSuccess(username);

            return result;

        } catch (InvalidCredentialsException | UserNotFoundException ex) {

            // Register failed attempt (policy decides outcome)
            LoginAttemptResult attempt = loginAttemptPolicy.registerAttempt(username);

            if (!attempt.allowed()) {
                metrics.recordFailure(username, "User locked");
                throw new UserLockedException(username);
            }

            metrics.recordFailure(username, "Invalid credentials");
            throw ex;
        }
    }
}