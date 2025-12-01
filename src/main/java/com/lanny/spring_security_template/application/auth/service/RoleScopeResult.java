package com.lanny.spring_security_template.application.auth.service;

import java.util.List;
import java.util.Objects;

/**
 * Immutable value object representing resolved roles and scopes for a user.
 *
 * <p>
 * Produced by {@link RoleScopeResolver}, consumed by application-level
 * services such as {@code MeService}.
 * </p>
 *
 * <h2>Design Guarantees:</h2>
 * <ul>
 * <li>Lists are defensive-copied and unmodifiable</li>
 * <li>Null-safe construction</li>
 * <li>Convenience helpers for role/scope inspection</li>
 * <li>Pure Value Object (DDD)</li>
 * </ul>
 */
public record RoleScopeResult(
                List<String> roleNames,
                List<String> scopeNames) {

        public RoleScopeResult {
                Objects.requireNonNull(roleNames, "roleNames must not be null");
                Objects.requireNonNull(scopeNames, "scopeNames must not be null");

                // Defensive copies + immutability barrier
                roleNames = List.copyOf(roleNames);
                scopeNames = List.copyOf(scopeNames);
        }

        /*
         * ============================================================
         * Convenience Helpers
         * ============================================================
         */

        public boolean hasRole(String role) {
                return role != null && roleNames.contains(role);
        }

        public boolean hasScope(String scope) {
                return scope != null && scopeNames.contains(scope);
        }

        public boolean hasAnyRole(List<String> roles) {
                if (roles == null)
                        return false;
                return roles.stream().anyMatch(roleNames::contains);
        }

        public boolean hasAnyScope(List<String> scopes) {
                if (scopes == null)
                        return false;
                return scopes.stream().anyMatch(scopeNames::contains);
        }

        public boolean hasAllRoles(List<String> roles) {
                if (roles == null)
                        return false;
                return roleNames.containsAll(roles);
        }

        public boolean hasAllScopes(List<String> scopes) {
                if (scopes == null)
                        return false;
                return scopeNames.containsAll(scopes);
        }
}
