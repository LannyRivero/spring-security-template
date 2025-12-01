package com.lanny.spring_security_template.infrastructure.mapper;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;

/**
 * Mapper responsible for converting between primitive persistence-layer
 * representations (Strings) and rich domain Value Objects (Role, Scope).
 *
 * <p>
 * This class lives in the infrastructure layer because:
 * - The domain must not depend on primitive or unvalidated data.
 * - Adapters (persistence, APIs) often operate with Strings.
 * - Conversion is an anti-corruption layer protecting the domain.
 * </p>
 *
 * <p>
 * All transformations are safe, deterministic, and idempotent.
 * </p>
 */
public final class DomainModelMapper {

    private DomainModelMapper() {
        // Utility class – no instances allowed.
    }

    // ------------------------------------------------------------
    // ROLE CONVERSION
    // ------------------------------------------------------------

    /**
     * Converts a list of raw role names (Strings) into a list of
     * domain {@link Role} VOs with empty scope sets.
     *
     * @param rawRoles raw role strings, e.g., ["ROLE_ADMIN", "user"]
     */
    public static List<Role> toRoles(List<String> rawRoles) {
        if (rawRoles == null)
            return List.of();

        return rawRoles.stream()
                .filter(r -> r != null && !r.isBlank())
                .map(r -> new Role(r, Set.of())) // Domain Role enforces normalization
                .toList();
    }

    /**
     * Converts a domain list of {@link Role} objects into Strings
     * suitable for persistence or DTO output.
     */
    public static List<String> toRoleStrings(List<Role> roles) {
        if (roles == null)
            return List.of();

        return roles.stream()
                .map(Role::name)
                .toList();
    }

    // ------------------------------------------------------------
    // SCOPE CONVERSION
    // ------------------------------------------------------------

    /**
     * Converts raw scope strings ("resource:action") into domain {@link Scope} VOs.
     */
    public static List<Scope> toScopes(List<String> rawScopes) {
        if (rawScopes == null)
            return List.of();

        return rawScopes.stream()
                .filter(s -> s != null && !s.isBlank())
                .map(Scope::of) // Scope.of applies full validation & normalization
                .toList();
    }

    /**
     * Converts domain {@link Scope} objects to string representation.
     */
    public static List<String> toScopeStrings(List<Scope> scopes) {
        if (scopes == null)
            return List.of();

        return scopes.stream()
                .map(Scope::name)
                .toList();
    }

    // ------------------------------------------------------------
    // AUTHORITY AGGREGATION (ROLE + SCOPE)
    // ------------------------------------------------------------

    /**
     * Converts domain roles + scopes into Spring Security–compatible authorities,
     * e.g.:
     * - ROLE_ADMIN
     * - SCOPE_profile:read
     *
     * Useful for:
     * - JWT claim population
     * - UserDetails implementation
     */
    public static Set<String> toAuthorities(List<Role> roles, List<Scope> scopes) {
        Set<String> roleAuthorities = roles == null ? Set.of()
                : roles.stream()
                        .map(Role::name)
                        .collect(Collectors.toSet());

        Set<String> scopeAuthorities = scopes == null ? Set.of()
                : scopes.stream()
                        .map(scope -> "SCOPE_" + scope.name())
                        .collect(Collectors.toSet());

        roleAuthorities.addAll(scopeAuthorities);
        return Set.copyOf(roleAuthorities);
    }
}
