package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.valueobject.Scope;

import java.util.List;
import java.util.Set;

public final class RoleScopeResolver {

    private RoleScopeResolver() {
        // utility
    }

    public static RoleScopeResult resolve(
            String username,
            RoleProvider roleProvider,
            ScopePolicy scopePolicy) {
        Set<Role> roles = roleProvider.resolveRoles(username);
        Set<Scope> scopes = scopePolicy.resolveScopes(roles);

        List<String> roleNames = roles.stream()
                .map(Role::name)
                .toList();

        List<String> scopeNames = scopes.stream()
                .map(Scope::name)
                .toList();

        return new RoleScopeResult(roleNames, scopeNames);
    }
}
