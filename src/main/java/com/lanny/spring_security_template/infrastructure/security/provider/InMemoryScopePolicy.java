package com.lanny.spring_security_template.infrastructure.security.provider;

import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.ScopePolicy;

/**
 * Declarative, in-memory mapping between roles and scopes.
 * Safe for all profiles (dev/demo/prod) and easy to extend.
 */
@Component
@Profile({ "dev", "demo", "prod" })
public class InMemoryScopePolicy implements ScopePolicy {

    /**
     * Defines the scopes granted to each role.
     * Keys are role names; values are lists of resource:action strings.
     */
    private static final Map<String, List<String>> ROLE_SCOPES = Map.of(
            "ROLE_ADMIN", List.of("profile:read", "profile:write", "user:manage"),
            "ROLE_USER", List.of("profile:read"));

    /**
     * Resolves scopes based on the user's roles.
     * Defensive against null/empty input and invalid role or scope formats.
     */
    @Override
    public List<String> resolveScopes(List<String> roles) {
        if (roles == null || roles.isEmpty()) {
            return List.of();
        }

        return roles.stream()
                .filter(Objects::nonNull)
                .flatMap(role -> ROLE_SCOPES.getOrDefault(role, List.of()).stream())
                .filter(scope -> scope.matches("^[a-z]+:[a-z]+$")) // ✅ validate resource:action format
                .distinct()
                .collect(Collectors.toList());
    }
}
