package com.lanny.spring_security_template.application.auth.port.out;

import java.util.List;
import java.util.Optional;

public interface UserAccountGateway {
    Optional<AuthUser> findByUsernameOrEmail(String usernameOrEmail);

    void save(AuthUser user); // para /register (perfil dev)

    record AuthUser(String id, String username, String email, String passwordHash, boolean enabled, List<String> roles,
            List<String> scopes) {
    }
}