package com.lanny.spring_security_template.application.auth.service;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import com.lanny.spring_security_template.application.auth.port.out.RefreshTokenStore;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;

import lombok.RequiredArgsConstructor;

/**
 * Pure password change use-case logic.
 *
 * Clean: no logging, no MDC, no auditing, no metrics.
 * All cross-cutting concerns are handled by the AuthUseCase decorator.
 */
@Service
@RequiredArgsConstructor
public class ChangePasswordService {

    private final UserAccountGateway userAccountGateway;
    private final RefreshTokenStore refreshTokenStore;
    private final PasswordHasher passwordHasher;
    private final PasswordPolicy passwordPolicy;

    @Transactional
    public void changePassword(String username, String currentPassword, String newPassword) {

        if (username == null || username.isBlank() ||
                currentPassword == null || currentPassword.isBlank() ||
                newPassword == null || newPassword.isBlank()) {
            throw new IllegalArgumentException("Username and passwords must not be blank");
        }

        // 1. Retrieve user (generic error → prevent user enumeration)
        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid current password"));

        // 2. Verify current password
        if (!passwordHasher.matches(currentPassword, user.passwordHash().value())) {
            throw new InvalidCredentialsException("Invalid current password");
        }

        // 3. Validate new password policy
        passwordPolicy.validate(newPassword);

        // 4. Hash new password and update
        PasswordHash newHash = PasswordHash.of(passwordHasher.hash(newPassword));
        User updatedUser = user.withChangedPassword(newHash);
        userAccountGateway.update(updatedUser);

        // 5. Invalidate all existing refresh tokens
        refreshTokenStore.deleteAllForUser(username);
    }
}
