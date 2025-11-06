package com.lanny.spring_security_template.infrastructure.persistence.jpa;

import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.UserEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.repository.UserJpaRepository;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
@Profile({ "dev", "prod" })
public class UserAccountJpaAdapter implements UserAccountGateway {

    private final UserJpaRepository userRepository;

    public UserAccountJpaAdapter(UserJpaRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Optional<User> findByUsernameOrEmail(String usernameOrEmail) {
        Optional<UserEntity> entityOpt = userRepository.findByUsernameOrEmail(usernameOrEmail);
        return entityOpt.map(this::toDomain);
    }

    @SuppressWarnings("null")
    @Override
    public void save(User user) {
        userRepository.save(toEntity(user));
    }

    private User toDomain(UserEntity entity) {
        return new User(
                entity.getId(),
                entity.getUsername(),
                entity.getEmail(),
                entity.getPasswordHash(),
                entity.isEnabled(),
                entity.getRoles().stream().map(r -> r.getName()).toList(),
                entity.getScopes().stream().map(s -> s.getName()).toList());
    }

    private UserEntity toEntity(User domain) {
        var entity = new UserEntity();
        entity.setId(domain.id());
        entity.setUsername(domain.username());
        entity.setEmail(domain.email());
        entity.setPasswordHash(domain.passwordHash());
        entity.setEnabled(domain.isEnabled());
        // roles/scopes: se pueden mapear aquí si gestionas creación
        return entity;
    }
}
