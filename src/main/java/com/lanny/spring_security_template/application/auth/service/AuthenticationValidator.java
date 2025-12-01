package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;

import lombok.RequiredArgsConstructor;

/**
 * Pure authentication validation logic (no logging, no MDC).
 *
 * All cross-cutting concerns (logging, audit, MDC) are handled by
 * AuthUseCaseLoggingDecorator and infrastructure adapters.
 */
@RequiredArgsConstructor
public class AuthenticationValidator {

    private final UserAccountGateway userAccountGateway;
    private final PasswordHasher passwordHasher;

    /**
     * Validates login credentials and returns the corresponding User.
     *
     * @param cmd login command
     * @return validated User
     */
    public User validate(LoginCommand cmd) {
        String username = cmd.username();

        // 1. Retrieve user (generic error to avoid enumeration)
        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid username or password"));

        // 2. Validate user state (locked, disabled, etc.)
        user.ensureCanAuthenticate();

        // 3. Validate password
        if (!passwordHasher.matches(cmd.password(), user.passwordHash().value())) {
            throw new InvalidCredentialsException("Invalid username or password");
        }

        return user;
    }
}
