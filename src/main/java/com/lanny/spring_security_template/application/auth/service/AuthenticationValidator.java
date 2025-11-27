package com.lanny.spring_security_template.application.auth.service;

import org.slf4j.MDC;
import org.springframework.stereotype.Service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Validates user authentication credentials and account state.
 *
 * <p>
 * Prevents user enumeration attacks by returning generic errors when
 * username or password validation fails. Only throws precise domain
 * exceptions internally (e.g., {@link InvalidCredentialsException}).
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class AuthenticationValidator {

    private final UserAccountGateway userAccountGateway;
    private final PasswordHasher passwordHasher;

    /**
     * Validates the provided login credentials and returns the corresponding
     * {@link User}.
     *
     * @param cmd login command containing username/email and password
     * @return validated {@link User}
     * @throws InvalidCredentialsException if credentials are invalid or user cannot
     *                                     authenticate
     */
    public User validate(LoginCommand cmd) {
        String username = cmd.username();
        String traceId = MDC.get("traceId");

        log.debug("[AUTH_VALIDATION] user={} trace={}", username, traceId);

        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid username or password"));

        user.ensureCanAuthenticate();

        if (!passwordHasher.matches(cmd.password(), user.passwordHash().value())) {
            log.warn("[AUTH_FAIL] user={} trace={} reason=invalid_password", username, traceId);
            throw new InvalidCredentialsException("Invalid username or password");
        }

        log.info("[AUTH_VALIDATION_OK] user={} trace={}", username, traceId);
        return user;
    }
}
