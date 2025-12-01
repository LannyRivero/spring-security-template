package com.lanny.spring_security_template.application.auth.service;

import java.util.Set;

import org.springframework.stereotype.Service;

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
 * Application service responsible for returning authenticated user details.
 *
 * <p>
 * This service acts as an orchestration layer between the domain and
 * presentation layers
 * to provide a complete view of the authenticated user.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Retrieve a {@link User} entity from the {@link UserAccountGateway} by
 * username or email.</li>
 * <li>Resolve associated {@link Role}s using {@link RoleProvider}.</li>
 * <li>Compute effective {@link Scope}s via {@link ScopePolicy} (role-based
 * permission expansion).</li>
 * <li>Return a {@link MeResult} DTO containing the unified identity
 * information.</li>
 * </ul>
 *
 * <h2>Design Notes</h2>
 * <ul>
 * <li>Follows Clean Architecture principles: no dependencies on frameworks or
 * persistence models.</li>
 * <li>Encapsulates authorization view logic while keeping the domain pure.</li>
 * <li>Supports extension for future audit or metrics recording.</li>
 * </ul>
 *
 * <h2>Typical Usage</h2>
 * 
 * <pre>{@code
 * MeResult profile = meService.me(authenticatedUsername);
 * }</pre>
 *
 * <h2>Throws</h2>
 * <ul>
 * <li>{@link UsernameNotFoundException} if the user does not exist.</li>
 * </ul>
 *
 * @see com.lanny.spring_security_template.application.auth.result.MeResult
 * @see com.lanny.spring_security_template.domain.model.User
 * @see com.lanny.spring_security_template.domain.model.Role
 * @see com.lanny.spring_security_template.domain.model.Scope
 */
@Service
@RequiredArgsConstructor
public class MeService {

    private final UserAccountGateway userAccountGateway;
    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;

    /**
     * Retrieves identity details (roles, scopes) for the authenticated user.
     *
     * @param username The username or email of the current authenticated user.
     * @return A {@link MeResult} containing roles and scopes assigned to the user.
     * @throws UsernameNotFoundException if no user is found for the given
     *                                   identifier.
     */
    public MeResult me(String username) {
        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new UserNotFoundException(username));

        Set<Role> roles = roleProvider.resolveRoles(username);
        Set<Scope> scopes = scopePolicy.resolveScopes(roles);

        return new MeResult(
                user.id().value().toString(),
                username,
                roles.stream().map(Role::name).toList(),
                scopes.stream().map(Scope::name).toList());
    }
}
