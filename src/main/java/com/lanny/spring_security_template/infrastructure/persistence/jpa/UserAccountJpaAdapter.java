package com.lanny.spring_security_template.infrastructure.persistence.jpa;

import java.util.List;
import java.util.Optional;

import org.springframework.context.annotation.Profile;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.UserId;
import com.lanny.spring_security_template.domain.valueobject.Username;
import com.lanny.spring_security_template.infrastructure.mapper.DomainModelMapper;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.UserEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.repository.UserJpaRepository;

/**
 * JPA adapter implementing the {@link UserAccountGateway} outbound port.
 *
 * <p>
 * Acts as a bridge between domain aggregates and JPA entities.
 * Converts {@link UserEntity} ↔ {@link User} using factory methods
 * such as {@code User.rehydrate}.
 * </p>
 *
 * <p>
 * This class contains ONLY mapping and simple persistence logic.
 * All domain rules live inside the aggregate or services.
 * </p>
 */
@Component
@Profile({ "dev", "prod" })
public class UserAccountJpaAdapter implements UserAccountGateway {

    private final UserJpaRepository userRepository;

    public UserAccountJpaAdapter(UserJpaRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ======================================================================
    // QUERIES
    // ======================================================================

    @Override
    public Optional<User> findByUsernameOrEmail(String usernameOrEmail) {
        return userRepository.findByUsernameOrEmail(usernameOrEmail)
                .map(this::toDomain);
    }

    @Override
    public Optional<User> findById(String userId) {
        if (userId == null)
            return Optional.empty();
        return userRepository.fetchWithRelations(userId)
                .map(this::toDomain);
    }

    @Override
    public Optional<User> findByEmail(String email) {
        return userRepository.findByEmailIgnoreCase(email)
                .map(this::toDomain);
    }

    // ======================================================================
    // COMMANDS
    // ======================================================================

    @Override
    public void save(User user) {
        userRepository.save(toEntity(user));
    }

    @Override
    public void update(User user) {
        userRepository.save(toEntity(user));
    }

    @Override
    public void updateStatus(String userId, UserStatus status) {
        if (userId == null)
            return;
        userRepository.findById(userId).ifPresent(entity -> {
            entity.setEnabled(status == UserStatus.ACTIVE);
            userRepository.save(entity);
        });
    }

    // ======================================================================
    // ENTITY → DOMAIN
    // ======================================================================

    private User toDomain(UserEntity entity) {

        UserStatus status = entity.isEnabled()
                ? UserStatus.ACTIVE
                : UserStatus.DISABLED;

        List<String> roles = entity.getRoles().stream()
                .map(r -> r.getName())
                .toList();

        List<String> scopes = entity.getScopes().stream()
                .map(s -> s.getName())
                .toList();

        return User.rehydrate(
                UserId.from(entity.getId()),
                Username.of(entity.getUsername()),
                EmailAddress.of(entity.getEmail()),
                PasswordHash.of(entity.getPasswordHash()),
                status,
                DomainModelMapper.toRoles(roles),
                DomainModelMapper.toScopes(scopes));
    }

    // ======================================================================
    // DOMAIN → ENTITY
    // ======================================================================

    @NonNull
    private UserEntity toEntity(User domain) {
        UserEntity entity = new UserEntity();

        if (domain.id() != null) {
            entity.setId(domain.id().value().toString());
        }

        entity.setUsername(domain.username().value());
        entity.setEmail(domain.email().value());
        entity.setPasswordHash(domain.passwordHash().value());
        entity.setEnabled(domain.status() == UserStatus.ACTIVE);

        // Roles y scopes NO se setean aquí (se gestionan por repos dedicados)
        return entity;
    }

    @Override
    public Page<User> findAll(@NonNull Pageable pageable) {
        return userRepository.findAll(pageable)
                .map(this::toDomain);
    }

}
