package com.lanny.spring_security_template.application.auth.service;

import java.util.List;
import java.util.Set;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

/**
 * Resolves all roles and scopes for a given user.
 *
 * <p>
 * This utility combines the output of {@link RoleProvider} and
 * {@link ScopePolicy}
 * into a unified {@link RoleScopeResult} structure used by upper layers
 * (e.g. {@link MeService}) to expose user permissions.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Resolve roles associated with a given username.</li>
 * <li>Resolve effective scopes derived from those roles.</li>
 * <li>Normalize and deduplicate all roles and scopes.</li>
 * </ul>
 *
 * <h2>Design Notes</h2>
 * <ul>
 * <li>Stateless and deterministic utility (pure function).</li>
 * <li>Normalizes role names to standard prefix form (e.g.
 * {@code ROLE_ADMIN}).</li>
 * <li>Does not depend on Spring context — fully testable and reusable.</li>
 * </ul>
 *
 * <h2>Example Usage</h2>
 * 
 * <pre>{@code
 * RoleScopeResult result = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);
 * List<String> roles = result.roleNames();
 * List<String> scopes = result.scopeNames();
 * }</pre>
 */
public final class RoleScopeResolver {

    private RoleScopeResolver() {
        // utility class
    }

    /**
     * Resolves roles and scopes for the given username.
     *
     * @param username     user identifier
     * @param roleProvider provider for role resolution
     * @param scopePolicy  policy for scope derivation
     * @return {@link RoleScopeResult} containing normalized role and scope names
     */
    public static RoleScopeResult resolve(
            String username,
            RoleProvider roleProvider,
            ScopePolicy scopePolicy) {

        // Step 1: Resolve roles assigned to the user
        Set<Role> roles = roleProvider.resolveRoles(username);

        // Step 2: Derive scopes from those roles using policy
        Set<Scope> scopes = scopePolicy.resolveScopes(roles);

        // Step 3: Normalize and extract names
        List<String> roleNames = roles.stream()
                .map(Role::name)
                .distinct()
                .toList();

        List<String> scopeNames = scopes.stream()
                .map(Scope::name)
                .distinct()
                .toList();

        return new RoleScopeResult(roleNames, scopeNames);
    }
}
