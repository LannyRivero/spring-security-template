package com.lanny.spring_security_template.application.auth.port.out;

import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Optional;

/**
 * Outbound port that defines persistence operations for the {@link User}
 * aggregate.
 *
 * <p>
 * This port abstracts all user-related persistence concerns
 * (JPA, JDBC, Redis, in-memory, etc.) and keeps the application
 * layer infrastructure-agnostic.
 * </p>
 *
 * <p>
 * Responsibilities:
 * </p>
 * <ul>
 * <li>User lookup for authentication and authorization</li>
 * <li>User lifecycle management (create, update, status changes)</li>
 * <li>Administrative user listing with pagination</li>
 * </ul>
 */
public interface UserAccountGateway {

    /**
     * Find a user by username or email.
     *
     * @param usernameOrEmail raw username or email provided by the client
     * @return optional {@link User} aggregate
     */
    Optional<User> findByUsernameOrEmail(String usernameOrEmail);

    /**
     * Find a user by its internal identifier.
     *
     * @param userId domain-level user identifier
     * @return optional {@link User} aggregate
     */
    Optional<User> findById(String userId);

    /**
     * Find a user by email.
     *
     * @param email email address
     * @return optional {@link User} aggregate
     */
    Optional<User> findByEmail(String email);

    /**
     * Persist a newly created {@link User} aggregate.
     *
     * @param user fully constructed user aggregate
     */
    void save(User user);

    /**
     * Update an existing {@link User} aggregate.
     *
     * @param user modified user aggregate
     */
    void update(User user);

    /**
     * Update the account status of a user.
     *
     * @param userId target user identifier
     * @param status new account status
     */
    void updateStatus(String userId, UserStatus status);

    /**
     * Retrieve all users with pagination support.
     *
     * <p>
     * This operation is intended for administrative use cases
     * (user management panels, audits, reporting).
     * </p>
     *
     * @param pageable pagination and sorting information
     * @return paginated list of {@link User} aggregates
     */
    Page<User> findAll(Pageable pageable);
}
