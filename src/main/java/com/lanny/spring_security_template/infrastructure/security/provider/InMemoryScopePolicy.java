package com.lanny.spring_security_template.infrastructure.security.provider;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

/**
 * ============================================================
 * InMemoryScopePolicy
 * ============================================================
 *
 * <p>
 * In-memory implementation of {@link ScopePolicy} that resolves
 * authorization scopes based on a declarative role-to-scope mapping.
 * </p>
 *
 * <h2>Contract</h2>
 * <ul>
 * <li>Resolution is deterministic</li>
 * <li>Unknown roles resolve to an empty scope set</li>
 * <li>Returned scope sets are immutable</li>
 * <li>Methods never return {@code null}</li>
 * <li>Methods never throw exceptions</li>
 * </ul>
 *
 * <h2>Intended usage</h2>
 * <p>
 * This implementation is intended <b>exclusively for demo environments</b>
 * to validate RBAC + scope-based authorization flows without external
 * dependencies.
 * </p>
 *
 * <h2>Security characteristics</h2>
 * <ul>
 * <li>No user input influences scope resolution</li>
 * <li>No side effects or external calls</li>
 * <li>No persistence or caching</li>
 * </ul>
 *
 * <h2>Limitations</h2>
 * <ul>
 * <li>Scopes are hardcoded and not auditable</li>
 * <li>No tenant-awareness</li>
 * <li>No dynamic policy evaluation</li>
 * </ul>
 *
 * <h2>Production note</h2>
 * <p>
 * This policy is <b>NOT suitable for production</b>.
 * Production systems should replace it with:
 * </p>
 * <ul>
 * <li>Database-backed scope resolution</li>
 * <li>External IAM / authorization services</li>
 * <li>Policy engines (OPA / ABAC)</li>
 * </ul>
 */
@Component
@Profile({ "demo" })
public class InMemoryScopePolicy implements ScopePolicy {

        /**
         * Declarative role → scopes mapping.
         *
         * <p>
         * Keys are normalized role names (upper-case).
         * Values represent the complete set of scopes granted by each role.
         * </p>
         */
        private static final Map<String, Set<Scope>> ROLE_SCOPES = Map.of(
                        "ADMIN", Set.of(
                                        Scope.of("profile:read"),
                                        Scope.of("profile:write"),
                                        Scope.of("user:manage")),
                        "USER", Set.of(
                                        Scope.of("profile:read")));

        @Override
        public Set<Scope> resolveScopes(Set<Role> roles) {
                if (roles == null || roles.isEmpty()) {
                        return Set.of();
                }

                return roles.stream()
                                .flatMap(role -> ROLE_SCOPES
                                                .getOrDefault(role.name().toUpperCase(), Set.of())
                                                .stream())
                                .collect(Collectors.toUnmodifiableSet());
        }

        @Override
        public boolean hasScope(String scopeName, Set<Role> roles) {
                if (scopeName == null || scopeName.isBlank()) {
                        return false;
                }

                return resolveScopes(roles).stream()
                                .anyMatch(scope -> scope.name().equalsIgnoreCase(scopeName));
        }

        @Override
        public boolean can(String action, String resource, Set<Role> roles) {
                if (action == null || resource == null) {
                        return false;
                }

                return resolveScopes(roles).stream()
                                .anyMatch(scope -> scope.action().equalsIgnoreCase(action)
                                                && scope.resource().equalsIgnoreCase(resource));
        }
}
