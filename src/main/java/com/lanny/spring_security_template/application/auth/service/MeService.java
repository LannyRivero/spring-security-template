package com.lanny.spring_security_template.application.auth.service;

import java.util.Set;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.exception.UserNotFoundException;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

import lombok.RequiredArgsConstructor;

/**
 * Application service responsible for retrieving identity information
 * (roles and scopes) for an authenticated user.
 *
 * <p>
 * This service belongs strictly to the <strong>application layer</strong> and
 * contains no framework dependencies or cross-cutting concerns:
 * </p>
 * <ul>
 * <li>No logging</li>
 * <li>No MDC correlation</li>
 * <li>No auditing</li>
 * <li>No Spring Security interactions</li>
 * </ul>
 *
 * <p>
 * Its responsibility is purely to orchestrate:
 * </p>
 * <ol>
 * <li>Retrieve the domain {@link User}</li>
 * <li>Resolve assigned {@link Role roles}</li>
 * <li>Expand {@link Scope scopes} via {@link ScopePolicy}</li>
 * <li>Assemble a {@link MeResult} DTO for the transport layer</li>
 * </ol>
 *
 * <p>
 * Any logging, auditing or metrics must be handled externally by
 * {@code AuthUseCaseLoggingDecorator}.
 * </p>
 */
@RequiredArgsConstructor
public class MeService {

    private final UserAccountGateway userAccountGateway;
    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;

    /**
     * Retrieves identity information for the given username, resolving all roles
     * and scopes available to that user.
     *
     * <p>
     * The returned {@link MeResult} DTO contains:
     * </p>
     * <ul>
     * <li>The user's UUID (as string)</li>
     * <li>The canonical username</li>
     * <li>Normalized role names (e.g., {@code ROLE_ADMIN})</li>
     * <li>All effective scopes resolved from those roles</li>
     * </ul>
     *
     * @param username the authenticated username
     * @return a {@link MeResult} describing roles and scopes for the user
     *
     * @throws UserNotFoundException
     *                               if no user exists with this username or email
     */
    public MeResult me(String username) {

        // 1. Load user or fail with domain exception
        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new UserNotFoundException(username));

        // 2. Resolve domain roles from RoleProvider
        Set<Role> roles = roleProvider.resolveRoles(username);

        // 3. Expand scopes based on ScopePolicy rules
        Set<Scope> scopes = scopePolicy.resolveScopes(roles);

        // 4. Assemble DTO (transport layer object)
        return new MeResult(
                user.id().value().toString(),
                username,
                roles.stream().map(Role::name).toList(),
                scopes.stream().map(Scope::name).toList());
    }
}
