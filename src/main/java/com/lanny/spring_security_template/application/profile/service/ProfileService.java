package com.lanny.spring_security_template.application.profile.service;

import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.EmailAlreadyExistsException;
import com.lanny.spring_security_template.domain.exception.UserNotFoundException;
import com.lanny.spring_security_template.domain.model.User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Application service for user profile self-service operations.
 * <p>
 * Allows authenticated users to view and update their own profile
 * information. Unlike UserManagementService, this service operates
 * on the current user's own data only.
 * <p>
 * Operations are protected by the SCOPE_profile:read and SCOPE_profile:write
 * scopes, which are typically granted to all authenticated users.
 */
@Service
@Transactional(readOnly = true)
public class ProfileService {

    private final UserAccountGateway userAccountGateway;

    public ProfileService(UserAccountGateway userAccountGateway) {
        this.userAccountGateway = userAccountGateway;
    }

    /**
     * Retrieve the current user's profile information.
     *
     * @param userId current user's identifier (from JWT)
     * @return user aggregate with profile data
     * @throws UserNotFoundException if user not found
     */
    public User getProfile(String userId) {
        return userAccountGateway.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
    }

    /**
     * Update the current user's email address.
     * <p>
     * Validates that the new email is not already in use by another user.
     *
     * @param userId  current user's identifier (from JWT)
     * @param newEmail new email address
     * @throws UserNotFoundException        if user not found
     * @throws EmailAlreadyExistsException if email is already in use
     */
    @Transactional
    public void updateEmail(String userId, String newEmail) {
        // Verify user exists
        getProfile(userId);

        // Check if email is already in use by a different user
        userAccountGateway.findByEmail(newEmail)
                .ifPresent(existingUser -> {
                    if (!existingUser.id().value().toString().equals(userId)) {
                        throw new EmailAlreadyExistsException("Email already in use: " + newEmail);
                    }
                });

        // In a real implementation, you'd need a method to update just the email
        // For now, we'll need to add this to UserAccountGateway or create an updateEmail method
        // This is a simplified placeholder
        // TODO: Add updateEmail method to UserAccountGateway or reconstruct User with new email
        // TODO: Validate email format using EmailAddress.of(newEmail) before updating
    }
}
