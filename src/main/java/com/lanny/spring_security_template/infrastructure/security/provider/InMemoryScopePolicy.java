package com.lanny.spring_security_template.infrastructure.security.provider;

import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.valueobject.Scope;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Declarative, in-memory mapping between roles and scopes.
 * Now uses Value Objects (Role, Scope) and Set<Scope>.
 */
@Component
@Profile({ "dev", "demo", "prod" })
public class InMemoryScopePolicy implements ScopePolicy {

    /**
     * Declarative mapping:
     * ROLE_NAME → Set<Scope>
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
                .flatMap(role -> ROLE_SCOPES.getOrDefault(
                        role.name().toUpperCase(),
                        Set.of()).stream())
                .collect(Collectors.toUnmodifiableSet());
    }
}
