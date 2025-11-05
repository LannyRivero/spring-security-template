package com.lanny.spring_security_template.application.auth.port.out;

import java.util.List;
import java.util.Optional;

public interface UserAccountGateway {

    Optional<UserAccountRecord> findByUsernameOrEmail(String usernameOrEmail);

    void save(UserAccountRecord user);

    record UserAccountRecord(
            String id,
            String username,
            String email,
            String passwordHash,
            boolean enabled,
            List<String> roles,
            List<String> scopes) {
    }
}
