package com.lanny.spring_security_template.infrastructure.security.provider;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import com.lanny.spring_security_template.domain.model.Role;
import com.lanny.spring_security_template.domain.model.Scope;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@Profile({ "dev", "demo" })
public class InMemoryRoleProvider implements RoleProvider {

    @Override
    public Set<Role> resolveRoles(String username) {

        if ("admin".equalsIgnoreCase(username)) {
            return Set.of(
                    new Role(
                            "ADMIN",
                            Set.of(
                                    Scope.of("profile:read"),
                                    Scope.of("profile:write"),
                                    Scope.of("user:read"))));
        }

        return Set.of(
                new Role(
                        "USER",
                        Set.of(
                                Scope.of("profile:read"))));
    }
}
