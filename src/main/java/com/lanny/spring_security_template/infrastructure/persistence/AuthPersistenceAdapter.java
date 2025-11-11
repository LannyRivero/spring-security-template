package com.lanny.spring_security_template.infrastructure.persistence;

import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.Optional;

@Component
@Profile("demo") 
public class AuthPersistenceAdapter implements UserAccountGateway {

    @Override
    public Optional<User> findByUsernameOrEmail(String usernameOrEmail) {
        if ("admin".equalsIgnoreCase(usernameOrEmail)) {
            return Optional.of(new User(
                    "1",
                    "admin",
                    "admin@example.com",
                    "{noop}admin123",
                    UserStatus.ACTIVE,
                    List.of("ROLE_ADMIN"),
                    List.of("profile:read", "profile:write")
            ));
        }

        if ("user".equalsIgnoreCase(usernameOrEmail)) {
            return Optional.of(new User(
                    "2",
                    "user",
                    "user@example.com",
                    "{noop}user123",
                    UserStatus.ACTIVE,
                    List.of("ROLE_USER"),
                    List.of("profile:read")
            ));
        }

        return Optional.empty();
    }

    @Override
    public void save(User user) {
        // 🚀 No-op para demo (no persistimos realmente)
        System.out.printf("[DEMO] Simulating save of user: %s%n", user.username());
    }
}




