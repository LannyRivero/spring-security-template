package com.lanny.spring_security_template.infrastructure.security.provider;

import com.lanny.spring_security_template.application.auth.port.out.RoleProvider;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@Profile({ "dev", "demo", "prod" }) 
public class InMemoryRoleProvider implements RoleProvider {

    @Override
    public List<String> resolveRoles(String username) {
        //  Aquí puedes usar lógica real (consultar DB o API)
        // De momento, un mock básico:
        if ("admin".equalsIgnoreCase(username)) {
            return List.of("ROLE_ADMIN");
        }
        return List.of("ROLE_USER");
    }
}

