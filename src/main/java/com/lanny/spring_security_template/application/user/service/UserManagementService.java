package com.lanny.spring_security_template.application.user.service;

import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.UserNotFoundException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Application service for user management operations.
 * <p>
 * Provides administrative operations for listing, retrieving, and
 * updating user accounts. These operations are typically restricted
 * to users with appropriate scopes (e.g., SCOPE_users:read, SCOPE_users:write).
 * <p>
 * This service orchestrates domain logic and infrastructure adapters
 * following hexagonal architecture principles.
 */
@Service
@Transactional(readOnly = true)
public class UserManagementService {

    private final UserAccountGateway userAccountGateway;

    public UserManagementService(UserAccountGateway userAccountGateway) {
        this.userAccountGateway = userAccountGateway;
    }

    /**
     * List all users with pagination support.
     * <p>
     * Note: Current implementation loads all users and paginates in-memory.
     * For production systems with large user bases, implement repository-level
     * pagination.
     *
     * @param pageable pagination parameters (page number, size, sort)
     * @return paginated list of users
     */
    public Page<User> listUsers(Pageable pageable) {

        return userAccountGateway.findAll(pageable);

    }

    /**
     * Retrieve a specific user by ID.
     *
     * @param userId user identifier
     * @return user aggregate
     * @throws UserNotFoundException if user not found
     */
    public User getUserById(String userId) {
        return userAccountGateway.findById(userId)
                .orElseThrow(() -> new UserNotFoundException("User not found: " + userId));
    }

    /**
     * Update a user's account status.
     * <p>
     * Status transitions include:
     * - ACTIVE: Normal operation
     * - LOCKED: Temporarily suspended
     * - DISABLED: Administratively disabled
     * - DELETED: Soft-deleted
     *
     * @param userId    user identifier
     * @param newStatus target status
     * @throws UserNotFoundException if user not found
     */
    @Transactional
    public void updateUserStatus(String userId, UserStatus newStatus) {
        // Verify user exists first
        getUserById(userId);

        // Delegate to gateway for status update
        userAccountGateway.updateStatus(userId, newStatus);
    }

    /**
     * Delete a user (soft delete by setting status to DELETED).
     *
     * @param userId user identifier
     * @throws UserNotFoundException if user not found
     */
    @Transactional
    public void deleteUser(String userId) {
        updateUserStatus(userId, UserStatus.DELETED);
    }
}
