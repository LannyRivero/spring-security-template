package com.lanny.spring_security_template.infrastructure.persistence.jpa;

import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.springframework.context.annotation.Profile;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.UserId;
import com.lanny.spring_security_template.domain.valueobject.Username;
import com.lanny.spring_security_template.infrastructure.mapper.DomainModelMapper;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.RoleEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.UserEntity;
import com.lanny.spring_security_template.infrastructure.persistence.jpa.repository.UserJpaRepository;

/**
 * JPA adapter implementing the {@link UserAccountGateway}.
 *
 * <p>
 * This adapter is responsible ONLY for:
 * <ul>
 * <li>Loading persisted {@link UserEntity} instances</li>
 * <li>Rehydrating {@link User} domain aggregates</li>
 * <li>Persisting already-valid domain state</li>
 * </ul>
 *
 * <p>
 * It MUST NOT:
 * <ul>
 * <li>Apply business rules</li>
 * <li>Mutate domain invariants</li>
 * <li>Reconstruct entities field-by-field</li>
 * </ul>
 */
@SuppressWarnings("null")
@Component
@Profile({ "dev", "prod" })
public class UserAccountJpaAdapter implements UserAccountGateway {

    private final UserJpaRepository userRepository;

    public UserAccountJpaAdapter(UserJpaRepository userRepository) {
        this.userRepository = userRepository;
    }

    // ======================================================
    // QUERIES
    // ======================================================

    @Override
    public Optional<User> findByUsernameOrEmail(String value) {
        return userRepository.findByUsernameOrEmail(value)
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

    @Override
    public Page<User> findAll(@NonNull Pageable pageable) {
        return userRepository.findAll(pageable).map(this::toDomain);
    }

    // ======================================================
    // COMMANDS
    // ======================================================

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
            if (status == UserStatus.ACTIVE) {
                entity.enable();
            } else {
                entity.disable();
            }
            userRepository.save(entity);
        });
    }

    // ======================================================
    // ENTITY → DOMAIN
    // ======================================================

    @NonNull
    private User toDomain(@NonNull UserEntity entity) {

        Objects.requireNonNull(entity, "UserEntity must not be null");

        UserStatus status = entity.isEnabled()
                ? UserStatus.ACTIVE
                : UserStatus.DISABLED;

        List<String> roleNames = entity.getRoles().stream()
                .map(RoleEntity::getName)
                .toList();

        return Objects.requireNonNull(
                User.rehydrate(
                        UserId.from(entity.getId()),
                        Username.of(entity.getUsername()),
                        EmailAddress.of(entity.getEmail()),
                        PasswordHash.of(entity.getPasswordHash()),
                        status,
                        DomainModelMapper.toRoles(roleNames)),
                "Rehydrated User must not be null");
    }

    // ======================================================
    // DOMAIN → ENTITY
    // ======================================================

    @NonNull
    private UserEntity toEntity(@NonNull User domain) {

        Objects.requireNonNull(domain, "User domain object must not be null");

        if (domain.id() != null) {
            final String entityId = Objects.requireNonNull(
                    domain.id().toString(),
                    "UserId string representation must not be null");

            return userRepository.findById(entityId)
                    .map(existing -> Objects.requireNonNull(
                            existing.updateFromDomain(domain),
                            "Updated UserEntity must not be null"))
                    .orElseThrow(() -> new IllegalStateException("User not found: " + entityId));
        }

        return new UserEntity(
                Objects.requireNonNull(domain.username().value(), "Username must not be null"),
                Objects.requireNonNull(domain.email().value(), "Email must not be null"),
                Objects.requireNonNull(domain.passwordHash().value(), "Password hash must not be null"));
    }

}
