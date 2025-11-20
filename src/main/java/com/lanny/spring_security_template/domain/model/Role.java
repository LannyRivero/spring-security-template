package com.lanny.spring_security_template.domain.model;

import com.lanny.spring_security_template.domain.valueobject.Scope;

import java.util.Objects;
import java.util.Set;

/**
 * Rich domain Value Object representing a Role with normalized name and
 * associated scopes.
 *
 * <p>
 * Normalization rules (enterprise standard):
 * <ul>
 * <li>Trimmed</li>
 * <li>Uppercase</li>
 * <li>Always starts with "ROLE_"</li>
 * <li>Matches pattern ROLE_[A-Z0-9_-]+</li>
 * </ul>
 *
 * This ensures consistency with Spring Security and avoids malformed roles.
 */
public record Role(String name, Set<Scope> scopes) {

    public Role {
        Objects.requireNonNull(name, "Role name cannot be null");
        Objects.requireNonNull(scopes, "Role scopes cannot be null");

        // 1. Normalize
        name = normalize(name);

        // 2. Validate
        validateRoleName(name);

        // 3. Defensive copy
        scopes = Set.copyOf(scopes);
    }

    private static String normalize(String raw) {
        String n = raw.trim().toUpperCase();
        if (!n.startsWith("ROLE_")) {
            n = "ROLE_" + n;
        }
        return n;
    }

    private static void validateRoleName(String role) {
        if (!role.matches("ROLE_[A-Z0-9_-]+")) {
            throw new IllegalArgumentException(
                    "Invalid role format '" + role +
                            "'. Expected ROLE_[A-Z0-9_-]+");
        }
    }

    public boolean hasScope(String scopeName) {
        return scopes.stream()
                .anyMatch(scope -> scope.name().equalsIgnoreCase(scopeName));
    }

    public boolean hasScopeForResource(String resource) {
        return scopes.stream()
                .anyMatch(scope -> scope.resource().equalsIgnoreCase(resource));
    }

    public boolean can(String action, String resource) {
        return scopes.stream()
                .anyMatch(scope -> scope.action().equalsIgnoreCase(action)
                        && scope.resource().equalsIgnoreCase(resource));
    }

    public boolean isAdmin() {
        return "ROLE_ADMIN".equals(name);
    }

    public boolean isSystem() {
        return "ROLE_SYSTEM".equals(name);
    }

    public Role mergeWith(Role other) {
        Set<Scope> merged = new java.util.HashSet<>(this.scopes);
        merged.addAll(other.scopes);
        return new Role(this.name, merged);
    }

    public Set<String> toAuthorities() {
        Set<String> authorities = new java.util.HashSet<>();

        // name already normalized with ROLE_
        authorities.add(name);

        scopes.forEach(scope -> authorities.add("SCOPE_" + scope.name()));

        return authorities;
    }
}
