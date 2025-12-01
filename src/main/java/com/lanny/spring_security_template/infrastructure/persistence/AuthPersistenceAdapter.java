package com.lanny.spring_security_template.infrastructure.persistence;

import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.UserId;
import com.lanny.spring_security_template.domain.valueobject.Username;
import com.lanny.spring_security_template.infrastructure.mapper.DomainModelMapper;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.*;

@Component
@Profile("demo")
public class AuthPersistenceAdapter implements UserAccountGateway {

    private final Map<String, User> demoUsers = new HashMap<>();

    public AuthPersistenceAdapter() {

        demoUsers.put("1",
                User.rehydrate(
                        UserId.from("1"),
                        Username.of("admin"),
                        EmailAddress.of("admin@example.com"),
                        PasswordHash.of("{noop}admin123"),
                        UserStatus.ACTIVE,
                        DomainModelMapper.toRoles(List.of("ROLE_ADMIN")),
                        DomainModelMapper.toScopes(List.of("profile:read", "profile:write"))));

        demoUsers.put("2",
                User.rehydrate(
                        UserId.from("2"),
                        Username.of("user"),
                        EmailAddress.of("user@example.com"),
                        PasswordHash.of("{noop}user123"),
                        UserStatus.ACTIVE,
                        DomainModelMapper.toRoles(List.of("ROLE_USER")),
                        DomainModelMapper.toScopes(List.of("profile:read"))));
    }

    @Override
    public Optional<User> findByUsernameOrEmail(String usernameOrEmail) {
        return demoUsers.values().stream()
                .filter(u -> u.username().value().equalsIgnoreCase(usernameOrEmail)
                        || u.email().value().equalsIgnoreCase(usernameOrEmail))
                .findFirst();
    }

    @Override
    public Optional<User> findById(String userId) {
        return Optional.ofNullable(demoUsers.get(userId));
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return demoUsers.values().stream()
                .filter(u -> u.email().value().equalsIgnoreCase(email))
                .findFirst();
    }

    @Override
    public void save(User user) {
        demoUsers.put(user.id().value().toString(), user);
    }

    @Override
    public void update(User user) {
        demoUsers.put(user.id().value().toString(), user);
    }

    @Override
    public void updateStatus(String userId, UserStatus status) {
        demoUsers.computeIfPresent(userId, (id, oldUser) -> User.rehydrate(
                oldUser.id(),
                oldUser.username(),
                oldUser.email(),
                oldUser.passwordHash(),
                status,
                oldUser.roles(),
                oldUser.scopes()));
    }
}
