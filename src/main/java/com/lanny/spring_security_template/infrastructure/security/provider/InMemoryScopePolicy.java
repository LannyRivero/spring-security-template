package com.lanny.spring_security_template.infrastructure.security.provider;

import com.lanny.spring_security_template.application.auth.port.out.ScopePolicy;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@Profile({ "dev", "demo", "prod" })
public class InMemoryScopePolicy implements ScopePolicy {

    @Override
    public List<String> resolveScopes(List<String> roles) {
        List<String> scopes = new ArrayList<>();

        if (roles.contains("ROLE_ADMIN")) {
            scopes.add("profile:read");
            scopes.add("profile:write");
            scopes.add("user:manage");
        } else if (roles.contains("ROLE_USER")) {
            scopes.add("profile:read");
        }

        return scopes;
    }
}

