package com.lanny.spring_security_template.application.auth.service;

import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

/**
 * Pure functional resolver that produces the authoritative list of
 * roles and scopes for a given user.
 *
 * <p>
 * This component is intentionally static, stateless, and framework-agnostic.
 * It belongs in the Application layer and is reusable across use cases
 * such as authentication, authorization reports, and identity summaries.
 * </p>
 *
 * <h2>Responsibilities:</h2>
 * <ul>
 * <li>Fetch roles via {@link RoleProvider}</li>
 * <li>Expand scopes via {@link ScopePolicy}</li>
 * <li>Normalize, deduplicate, and order results deterministically</li>
 * </ul>
 *
 * <p>
 * Does NOT log, audit, or access infrastructure.
 * Cross-cutting belongs in decorators (e.g., AuthUseCaseLoggingDecorator).
 * </p>
 */
public final class RoleScopeResolver {

    private RoleScopeResolver() {
        // Utility class — no instances.
    }

    /**
     * Resolves roles and scopes for a given username in a fully deterministic,
     * pure-function style.
     *
     * @param username     the authenticated user identifier
     * @param roleProvider provider to resolve roles
     * @param scopePolicy  policy to derive scopes from roles
     * @return {@link RoleScopeResult} containing normalized role and scope names
     */
    public static RoleScopeResult resolve(
            String username,
            RoleProvider roleProvider,
            ScopePolicy scopePolicy) {

        Objects.requireNonNull(username, "username must not be null");
        Objects.requireNonNull(roleProvider, "roleProvider must not be null");
        Objects.requireNonNull(scopePolicy, "scopePolicy must not be null");

        // Step 1: Resolve roles assigned to the user
        Set<Role> roles = roleProvider.resolveRoles(username);

        // Step 2: Derive scopes using policy rules
        Set<Scope> scopes = scopePolicy.resolveScopes(roles);

        // Step 3: Normalize, sort, dedupe role names
        List<String> roleNames = roles.stream()
                .map(Role::name)
                .distinct()
                .sorted() // deterministic output for logging/tests
                .toList();

        // Step 4: Normalize, sort, dedupe scope names
        List<String> scopeNames = scopes.stream()
                .map(Scope::name)
                .distinct()
                .sorted()
                .toList();

        return new RoleScopeResult(roleNames, scopeNames);
    }
}
