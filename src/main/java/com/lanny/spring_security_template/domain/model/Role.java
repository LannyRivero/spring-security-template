package com.lanny.spring_security_template.domain.model;

import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

import com.lanny.spring_security_template.domain.exception.InvalidRoleException;

/**
 * Rich domain Value Object representing a Role with normalized name and scopes.
 *
 * Normalization:
 * - Trimmed
 * - Uppercase
 * - Always starts with "ROLE_"
 * - Pattern: ROLE_[A-Z0-9_-]+
 */
public record Role(String name, Set<Scope> scopes) {

    public Role {
        Objects.requireNonNull(name, "Role name cannot be null");
        Objects.requireNonNull(scopes, "Role scopes cannot be null");

        String normalized = normalize(name);
        validateRoleName(normalized);

        name = normalized;
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
            throw new InvalidRoleException(
                    "Invalid role format '" + role + "'. Expected ROLE_[A-Z0-9_-]+");
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
        Set<Scope> merged = new HashSet<>(this.scopes);
        merged.addAll(other.scopes);
        return new Role(this.name, merged);
    }

    public Set<String> toAuthorities() {
        Set<String> authorities = new HashSet<>();
        authorities.add(name); // ROLE_...
        scopes.forEach(scope -> authorities.add("SCOPE_" + scope.name()));
        return authorities;
    }
}
