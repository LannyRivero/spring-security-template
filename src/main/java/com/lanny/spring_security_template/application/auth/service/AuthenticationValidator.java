package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

/**
 * Validates authentication credentials and user account status.
 */
@Service
@RequiredArgsConstructor
public class AuthenticationValidator {

    private final UserAccountGateway userAccountGateway;
    private final PasswordHasher passwordHasher;

    public User validate(LoginCommand cmd) {
        User user = userAccountGateway.findByUsernameOrEmail(cmd.username())
                .orElseThrow(() -> new UsernameNotFoundException(cmd.username()));

        user.ensureCanAuthenticate();

        try {
            user.verifyPassword(cmd.password(), passwordHasher);
        } catch (InvalidCredentialsException e) {
            throw new InvalidCredentialsException("Invalid username or password");
        }

        return user;
    }
}
