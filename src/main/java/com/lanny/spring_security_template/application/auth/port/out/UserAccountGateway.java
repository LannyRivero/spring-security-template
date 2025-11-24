package com.lanny.spring_security_template.application.auth.port.out;

import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;

import java.util.Optional;

/**
 * Outbound port that defines the persistence operations for the {@link User}
 * aggregate.
 * <p>
 * This interface abstracts the infrastructure layer (JPA, Redis, Mongo, JDBC…)
 * ensuring that the application and domain layers remain fully decoupled.
 * <p>
 * It is responsible for retrieving, creating and updating user accounts,
 * including state transitions such as locking, disabling or soft-deleting
 * users.
 * <p>
 * Typical implementations:
 * <ul>
 * <li>JPA adapter with UserJpaEntity</li>
 * <li>Redis adapter (session or cache)</li>
 * <li>InMemory adapter (test profile)</li>
 * </ul>
 */
public interface UserAccountGateway {

    /**
     * Find a user by their username or email.
     * <p>
     * This is the most common lookup for authentication flows,
     * allowing flexible login with either field.
     *
     * @param usernameOrEmail raw username or email provided by the client
     * @return optional {@link User} aggregate if found
     */
    Optional<User> findByUsernameOrEmail(String usernameOrEmail);

    /**
     * Find a user by their unique internal identifier.
     *
     * @param userId domain-level user ID
     * @return optional {@link User} aggregate
     */
    Optional<User> findById(String userId);

    /**
     * Find a user by email only.
     * <p>
     * Useful for validation, uniqueness checks or admin-related operations.
     *
     * @param email valid email address
     * @return optional {@link User}
     */
    Optional<User> findByEmail(String email);

    /**
     * Persist a newly created {@link User} aggregate.
     * <p>
     * This is called typically during registration flows.
     *
     * @param user fully constructed User aggregate root
     */
    void save(User user);

    /**
     * Update an existing {@link User} aggregate.
     * <p>
     * The whole aggregate (roles, scopes, passwordHash, status) is persisted as a
     * unit.
     *
     * @param user modified User aggregate
     */
    void update(User user);

    /**
     * Update the account status for an existing user.
     * <p>
     * Status transitions include:
     * <ul>
     * <li>ACTIVE</li>
     * <li>LOCKED</li>
     * <li>DISABLED</li>
     * <li>DELETED (soft-delete)</li>
     * </ul>
     *
     * @param userId target user identifier
     * @param status new status for the user
     */
    void updateStatus(String userId, UserStatus status);
}
