package com.lanny.spring_security_template.infrastructure.persistence;

import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;

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
            return Optional.of(
                    new User(
                            "1",
                            Username.of("admin"),
                            EmailAddress.of("admin@example.com"),
                            PasswordHash.of("{noop}admin123"),  // DEMO ONLY
                            UserStatus.ACTIVE,
                            List.of("ROLE_ADMIN"),
                            List.of("profile:read", "profile:write")
                    )
            );
        }

        if ("user".equalsIgnoreCase(usernameOrEmail)) {
            return Optional.of(
                    new User(
                            "2",
                            Username.of("user"),
                            EmailAddress.of("user@example.com"),
                            PasswordHash.of("{noop}user123"), // DEMO ONLY
                            UserStatus.ACTIVE,
                            List.of("ROLE_USER"),
                            List.of("profile:read")
                    )
            );
        }

        return Optional.empty();
    }

    @Override
    public void save(User user) {
        // DEMO MODE: no persistence
        System.out.printf("[DEMO] Simulating save of user: %s%n", user.username().value());
    }
}





