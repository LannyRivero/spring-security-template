package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;
import java.util.Set;

/**
 * Rich domain Value Object representing a Role with its associated scopes.
 */
public record Role(String name, Set<Scope> scopes) {

    public Role {
        Objects.requireNonNull(name, "Role name cannot be null");
        Objects.requireNonNull(scopes, "Scope set cannot be null");

        name = name.toUpperCase();
        scopes = Set.copyOf(scopes);
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
                .anyMatch(scope -> scope.action().equalsIgnoreCase(action) &&
                        scope.resource().equalsIgnoreCase(resource));
    }

    public boolean isAdmin() {
        return "ADMIN".equalsIgnoreCase(name);
    }

    public boolean isSystem() {
        return "SYSTEM".equalsIgnoreCase(name);
    }

    public Role mergeWith(Role other) {
        Set<Scope> merged = new java.util.HashSet<>(this.scopes);
        merged.addAll(other.scopes);
        return new Role(this.name, merged);
    }

    public Set<String> toAuthorities() {
        Set<String> authorities = new java.util.HashSet<>();
        authorities.add("ROLE_" + name);
        scopes.forEach(scope -> authorities.add("SCOPE_" + scope.name()));
        return authorities;
    }
}
