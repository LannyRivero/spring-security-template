package com.lanny.spring_security_template.infrastructure.persistence;

import com.lanny.spring_security_template.application.auth.port.out.AuthPersistencePort;
import com.lanny.spring_security_template.domain.model.User;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
public class AuthPersistenceAdapter implements AuthPersistencePort {

    @Override
    public Optional<User> findByUsernameOrEmail(String usernameOrEmail) {
        if ("admin".equals(usernameOrEmail)) {
            return Optional.of(new User(
                    "1",
                    "admin",
                    "admin@example.com",
                    "$2a$10$Z3fEJ0pOfssHashP1x4w5Oj0ZbRA", 
                    true,
                    List.of("ADMIN"),
                    List.of("profile:read", "profile:write")
            ));
        }
        return Optional.empty();
    }
}

