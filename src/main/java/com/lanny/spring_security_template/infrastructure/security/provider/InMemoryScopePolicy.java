package com.lanny.spring_security_template.infrastructure.security.provider;

import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Simple in-memory implementation of ScopePolicy.
 *
 * Suitable for dev/demo/prod as long as scopes are declarative.
 * In enterprise systems, this can later be replaced with:
 * - DB-driven scopes,
 * - tenant-based scopes,
 * - dynamic IAM rules, etc.
 */
@Component
@Profile({"demo"})
public class InMemoryScopePolicy implements ScopePolicy {

        /**
         * Declarative role → scopes mapping
         */
        private static final Map<String, Set<Scope>> ROLE_SCOPES = Map.of(
                        "ADMIN", Set.of(
                                        Scope.of("profile:read"),
                                        Scope.of("profile:write"),
                                        Scope.of("user:manage")),
                        "USER", Set.of(
                                        Scope.of("profile:read")));

        // ============================================================
        // 1) RESOLVE SCOPES
        // ============================================================
        @Override
        public Set<Scope> resolveScopes(Set<Role> roles) {
                if (roles == null || roles.isEmpty()) {
                        return Set.of();
                }

                return roles.stream()
                                .flatMap(role -> ROLE_SCOPES.getOrDefault(role.name().toUpperCase(), Set.of())
                                                .stream())
                                .collect(Collectors.toUnmodifiableSet());
        }

        // ============================================================
        // 2) CHECK IF USER HAS A SPECIFIC SCOPE
        // ============================================================
        @Override
        public boolean hasScope(String scopeName, Set<Role> roles) {
                if (scopeName == null || scopeName.isBlank()) {
                        return false;
                }

                Set<Scope> resolved = resolveScopes(roles);
                return resolved.stream().anyMatch(scope -> scope.name().equalsIgnoreCase(scopeName));
        }

        // ============================================================
        // 3) CHECK FINE-GRAINED PERMISSIONS (resource + action)
        // ============================================================
        @Override
        public boolean can(String action, String resource, Set<Role> roles) {
                if (action == null || resource == null) {
                        return false;
                }

                Set<Scope> resolved = resolveScopes(roles);

                return resolved.stream().anyMatch(scope -> scope.action().equalsIgnoreCase(action)
                                && scope.resource().equalsIgnoreCase(resource));
        }
}
