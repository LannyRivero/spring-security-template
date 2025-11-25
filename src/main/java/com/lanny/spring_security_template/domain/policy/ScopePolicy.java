package com.lanny.spring_security_template.domain.policy;

import java.util.Set;

import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;

/**
 * Domain Policy responsible for resolving and validating fine-grained
 * permissions (Scopes) from a given set of {@link Role} aggregates.
 *
 * <p>
 * This interface expresses the core authorization rules of the domain,
 * independent from any persistence or infrastructure details.
 * </p>
 *
 * <p>
 * The ScopePolicy is the central authorization mechanism used by:
 * </p>
 * <ul>
 * <li>Login flows – to determine which scopes must be placed in the JWT</li>
 * <li>Access enforcement – via Scope-based {@code @PreAuthorize}</li>
 * <li>Role–Scope derivation – static, dynamic or context-dependent</li>
 * </ul>
 *
 * <p>
 * Typical responsibilities:
 * </p>
 * <ul>
 * <li>Static scope inheritance defined per role</li>
 * <li>Dynamic rules such as: ADMIN ⇒ all scopes</li>
 * <li>Tenant-based overrides (future extension)</li>
 * <li>Contextual scopes for resources (RBAC + ABAC)</li>
 * </ul>
 *
 * <p>
 * A concrete implementation should live in <strong>infrastructure</strong>,
 * while this interface remains pure domain.
 * </p>
 */
public interface ScopePolicy {

    /**
     * Computes the full set of {@link Scope} objects granted by the provided
     * collection of {@link Role} aggregates.
     *
     * <p>
     * Concrete policies may implement different authorization models:
     * </p>
     * <ul>
     * <li>Union of role-declared scopes</li>
     * <li>Implicit inheritance (ADMIN → all scopes)</li>
     * <li>Tenant or environment modifiers</li>
     * </ul>
     *
     * @param roles the set of roles granted to the user
     * @return the full resolved set of effective scopes
     */
    Set<Scope> resolveScopes(Set<Role> roles);

    /**
     * Determines whether the provided roles collectively grant permission
     * to perform an action on a resource.
     *
     * <p>
     * This is the ABAC-style version of authorization:
     * </p>
     * 
     * <pre>
     *   can("write", "simulation", roles)
     *   → checks for scope: "simulation:write"
     * </pre>
     *
     * @param action   the name of the action (e.g., "read", "write", "delete")
     * @param resource the resource name (e.g., "profile", "simulation")
     * @param roles    the roles to evaluate
     * @return true if the access is permitted
     */
    boolean can(String action, String resource, Set<Role> roles);

    /**
     * Checks whether the provided roles grant the given Scope by name.
     * <p>
     * Utility method often used by controllers or method security:
     * 
     * <pre>
     * hasScope("profile:read", roles)
     * </pre>
     *
     * @param scopeName the exact scope name (e.g. "profile:read")
     * @param roles     the granted roles
     * @return true if the scope is granted
     */
    boolean hasScope(String scopeName, Set<Role> roles);
}
