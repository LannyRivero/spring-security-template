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
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;
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

    // =====================================================
    // ENTITY → DOMAIN
    // =====================================================
    private User toDomain(UserEntity entity) {

        UserStatus status = entity.isEnabled() ? UserStatus.ACTIVE : UserStatus.DISABLED;

        List<String> roles = entity.getRoles().stream()
                .map(r -> r.getName())
                .toList();

        List<String> scopes = entity.getScopes().stream()
                .map(s -> s.getName())
                .toList();

        return new User(
                String.valueOf(entity.getId()),
                Username.of(entity.getUsername()),
                EmailAddress.of(entity.getEmail()),
                PasswordHash.of(entity.getPasswordHash()),
                status,
                roles,
                scopes);
    }

    // =====================================================
    // DOMAIN → ENTITY
    // =====================================================
    @NonNull
    private UserEntity toEntity(User domain) {
        UserEntity entity = new UserEntity();
        
        if (domain.id() != null) {
            try {
                entity.setId(domain.id().value().toString());

            } catch (NumberFormatException ex) {
                throw new IllegalStateException("Domain user ID must be convertible to Long");
            }
        }

        entity.setUsername(domain.username().value());
        entity.setEmail(domain.email().value());
        entity.setPasswordHash(domain.passwordHash().value());
        entity.setEnabled(domain.status() == UserStatus.ACTIVE);

        // ⚠️ Importante
        // NO seteamos roles/scopes aquí porque esas relaciones se gestionan
        // con entidades RoleEntity / ScopeEntity.
        // Esto evita problemas de cascada en JPA.

        return entity;
    }
}
