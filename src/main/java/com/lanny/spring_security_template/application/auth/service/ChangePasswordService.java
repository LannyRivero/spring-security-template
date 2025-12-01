package com.lanny.spring_security_template.application.auth.service;

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
 * <p>
 * This application service encapsulates the domain flow required to change
 * a user's password:
 * </p>
 *
 * <ol>
 * <li>Validate non-blank input parameters.</li>
 * <li>Load the user from the {@link UserAccountGateway}.</li>
 * <li>Verify the current password using {@link PasswordHasher}.</li>
 * <li>Validate the new password against the configured
 * {@link PasswordPolicy}.</li>
 * <li>Hash and persist the new password.</li>
 * <li>Invalidate all existing refresh tokens for the user via
 * {@link RefreshTokenStore}.</li>
 * </ol>
 *
 * <p>
 * Responsibilities are strictly limited to orchestrating domain behaviour;
 * there is:
 * </p>
 * <ul>
 * <li>No logging</li>
 * <li>No MDC / correlation IDs</li>
 * <li>No auditing or metrics</li>
 * <li>No Spring annotations in the class itself</li>
 * </ul>
 *
 * Cross-cutting concerns belong to decorators and infrastructure adapters.
 */
@RequiredArgsConstructor
public class ChangePasswordService {

    private final UserAccountGateway userAccountGateway;
    private final RefreshTokenStore refreshTokenStore;
    private final PasswordHasher passwordHasher;
    private final PasswordPolicy passwordPolicy;

    /**
     * Changes the password for the given user, enforcing current password
     * verification, password policy validation and token invalidation.
     *
     * @param username        identifier of the user requesting the change
     * @param currentPassword current raw password used for verification
     * @param newPassword     new raw password to be validated and persisted
     *
     * @throws IllegalArgumentException    if any argument is {@code null} or blank
     * @throws InvalidCredentialsException if the user does not exist or the current
     *                                     password does not match
     * @throws RuntimeException            if the underlying policy or gateway
     *                                     implementations raise domain-specific
     *                                     errors
     */
    public void changePassword(String username, String currentPassword, String newPassword) {

        if (username == null || username.isBlank() ||
                currentPassword == null || currentPassword.isBlank() ||
                newPassword == null || newPassword.isBlank()) {
            throw new IllegalArgumentException("Username and passwords must not be blank");
        }

        // 1. Retrieve user (generic error → prevent enumeration)
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
