package com.lanny.spring_security_template.application.auth.service;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.List;
import java.util.Set;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

/**
 * Unit tests for {@link RoleScopeResolver}.
 * Compatible with real domain model of Role and Scope.
 */
class RoleScopeResolverTest {

    private final RoleProvider roleProvider = mock(RoleProvider.class);
    private final ScopePolicy scopePolicy = mock(ScopePolicy.class);

    private static Role createRole(String name, Set<Scope> scopes) {
        return new Role(name, scopes);
    }

    @Test
    @DisplayName(" should resolve roles and scopes correctly for given user")
    void testShouldResolveRolesAndScopes() {
        // Arrange
        String username = "lanny";

        // Define some domain-valid scopes
        Scope profileRead = Scope.of("profile:read");
        Scope simulationRun = Scope.of("simulation:run");

        // Roles with attached scopes
        Role admin = createRole("admin", Set.of(profileRead, simulationRun));
        Role user = createRole("user", Set.of(profileRead));

        Set<Role> roles = Set.of(admin, user);
        Set<Scope> scopes = Set.of(profileRead, simulationRun);

        when(roleProvider.resolveRoles(username)).thenReturn(roles);
        when(scopePolicy.resolveScopes(roles)).thenReturn(scopes);

        // Act
        RoleScopeResult result = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // Assert
        assertThat(result.roleNames())
                .containsExactlyInAnyOrder("ROLE_ADMIN", "ROLE_USER");

        assertThat(result.scopeNames())
                .containsExactlyInAnyOrder("profile:read", "simulation:run");

        verify(roleProvider).resolveRoles(username);
        verify(scopePolicy).resolveScopes(roles);
    }

    @Test
    @DisplayName(" should return empty lists when no roles or scopes are resolved")
    void testShouldReturnEmptyWhenNoRolesOrScopes() {
        String username = "ghost";

        when(roleProvider.resolveRoles(username)).thenReturn(Set.of());
        when(scopePolicy.resolveScopes(Set.of())).thenReturn(Set.of());

        RoleScopeResult result = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        assertThat(result.roleNames()).isEmpty();
        assertThat(result.scopeNames()).isEmpty();
    }

    @Test
    @DisplayName(" should normalize role names automatically and merge duplicates")
    void testShouldNormalizeRoleNames() {
        // Arrange
        String username = "dup";
        Scope s1 = Scope.of("data:read");

        // "role_user" y "USER" se normalizan ambos a "ROLE_USER"
        Role r1 = createRole("role_user", Set.of(s1));
        Role r2 = createRole("USER", Set.of(s1));

        // Creamos una lista y la convertimos a Set al mockear el provider
        List<Role> duplicatedRoles = List.of(r1, r2);
        Set<Role> roles = new java.util.HashSet<>(duplicatedRoles);

        Set<Scope> scopes = Set.of(s1);

        when(roleProvider.resolveRoles(username)).thenReturn(roles);
        when(scopePolicy.resolveScopes(roles)).thenReturn(scopes);

        // Act
        RoleScopeResult result = RoleScopeResolver.resolve(username, roleProvider, scopePolicy);

        // Assert
        assertThat(result.roleNames())
                .containsExactly("ROLE_USER");

        assertThat(result.scopeNames())
                .containsExactly("data:read");
    }

}
