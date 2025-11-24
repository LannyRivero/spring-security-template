package com.lanny.spring_security_template.domain.policy;

import java.util.Set;

import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;

/**
 * Domain Policy for resolving and validating fine-grained permissions (Scopes)
 * based on a user's set of Roles.
 *
 * This abstraction allows:
 * - Static scopes inside roles
 * - Dynamic scopes (e.g., ADMIN inherits all)
 * - Tenant-based or contextual scopes (optional future extension)
 */
public interface ScopePolicy {

    /**
     * Resolves all scopes granted by the given set of roles.
     * This may apply implicit rules, such as ADMIN = all scopes.
     */
    Set<Scope> resolveScopes(Set<Role> roles);

    /**
     * Checks whether the given roles collectively grant permission
     * to perform the specified action on a resource.
     */
    boolean can(String action, String resource, Set<Role> roles);

    /**
     * Checks whether the given roles grant permission for a specific scope.
     * Example: can("simulation:write", roles)
     */
    boolean hasScope(String scopeName, Set<Role> roles);
}
