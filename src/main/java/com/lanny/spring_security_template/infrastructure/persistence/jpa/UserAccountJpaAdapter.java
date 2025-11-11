package com.lanny.spring_security_template.infrastructure.persistence.jpa;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.springframework.context.annotation.Profile;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.UserEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.repository.UserJpaRepository;

@Component
@Profile({ "dev", "prod" })
public class UserAccountJpaAdapter implements UserAccountGateway {

    private final UserJpaRepository userRepository;

    public UserAccountJpaAdapter(UserJpaRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<User> findByUsernameOrEmail(String usernameOrEmail) {
        return userRepository.findByUsernameOrEmail(usernameOrEmail)
                .filter(Objects::nonNull)
                .map(this::toDomain);
    }

    @Override
    public void save(User user) {
        if (user == null) {
            throw new IllegalArgumentException("User must not be null");
        }
        userRepository.save(toEntity(user));
    }

    /** ✅ Convierte entidad JPA → modelo de dominio */
    private User toDomain(UserEntity entity) {
        UserStatus status = entity.isEnabled() ? UserStatus.ACTIVE : UserStatus.DISABLED;

        List<String> roles = entity.getRoles().stream()
                .map(r -> r.getName())
                .toList();

        List<String> scopes = entity.getScopes().stream()
                .map(s -> s.getName())
                .toList();

        return new User(
                entity.getId(),
                entity.getUsername(),
                entity.getEmail(),
                entity.getPasswordHash(),
                status,
                roles,
                scopes);
    }
    /** ✅ Convierte modelo de dominio → entidad JPA */
    @NonNull
    private UserEntity toEntity(User domain) {
        UserEntity entity = new UserEntity();
        entity.setId(domain.id());
        entity.setUsername(domain.username());
        entity.setEmail(domain.email());
        entity.setPasswordHash(domain.passwordHash());
        // ✅ Traducimos el enum a boolean
        entity.setEnabled(domain.status() == UserStatus.ACTIVE);
        return entity;
    }
}
