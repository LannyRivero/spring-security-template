package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.application.auth.result.MeResult;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Set;

@Service
@RequiredArgsConstructor
public class MeService {

    private final UserAccountGateway userAccountGateway;
    private final RoleProvider roleProvider;
    private final ScopePolicy scopePolicy;

    public MeResult me(String username) {

        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        Set<Role> roles = roleProvider.resolveRoles(username);
        Set<Scope> scopes = scopePolicy.resolveScopes(roles);

        return new MeResult(
                user.id().value().toString(),
                username,
                roles.stream().map(Role::name).toList(),
                scopes.stream().map(Scope::name).toList()
        );
    }
}
