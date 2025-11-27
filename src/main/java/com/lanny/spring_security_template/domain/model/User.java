package com.lanny.spring_security_template.domain.model;

import java.util.List;
import java.util.Objects;

import com.lanny.spring_security_template.domain.exception.UserDeletedException;
import com.lanny.spring_security_template.domain.exception.UserDisabledException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.UserId;
import com.lanny.spring_security_template.domain.valueobject.Username;

/**
 * Aggregate root representing a system user.
 *
 * <p>
 * Applies all domain rules related to authentication, status validation,
 * password verification and identity consistency, while keeping all fields
 * immutable.
 * </p>
 *
 * <p>
 * This aggregate is pure domain code: it contains no references to
 * infrastructure, frameworks or annotations.
 * </p>
 */
public final class User {

    private final UserId id;
    private final Username username;
    private final EmailAddress email;
    private final PasswordHash passwordHash;
    private final UserStatus status;
    private final List<String> roles;
    private final List<String> scopes;

    // ======================================================
    // CONSTRUCTOR PRIVADO
    // ======================================================
    private User(
            UserId id,
            Username username,
            EmailAddress email,
            PasswordHash passwordHash,
            UserStatus status,
            List<String> roles,
            List<String> scopes) {
        this.id = Objects.requireNonNull(id);
        this.username = Objects.requireNonNull(username);
        this.email = Objects.requireNonNull(email);
        this.passwordHash = Objects.requireNonNull(passwordHash);
        this.status = Objects.requireNonNull(status);
        this.roles = List.copyOf(roles);
        this.scopes = List.copyOf(scopes);
    }

    // ======================================================
    // FACTORY METHODS
    // ======================================================

    /**
     * Creates a new active user with default roles/scopes.
     * Used typically in registration flows (dev/admin).
     */
    public static User createNew(
            Username username,
            EmailAddress email,
            PasswordHash passwordHash,
            List<String> roles,
            List<String> scopes) {
        return new User(
                UserId.newId(),
                username,
                email,
                passwordHash,
                UserStatus.ACTIVE,
                sanitize(roles),
                sanitize(scopes));
    }

    /**
     * Reconstructs an existing user (hydration from persistence).
     */
    public static User rehydrate(
            UserId id,
            Username username,
            EmailAddress email,
            PasswordHash passwordHash,
            UserStatus status,
            List<String> roles,
            List<String> scopes) {
        return new User(
                id,
                username,
                email,
                passwordHash,
                status,
                sanitize(roles),
                sanitize(scopes));
    }

    // ======================================================
    // DOMAIN RULES
    // ======================================================

    /**
     * Ensures the user can authenticate.
     * Throws domain exceptions depending on status:
     * - LOCKED → UserLockedException
     * - DISABLED → UserDisabledException
     * - DELETED → UserDeletedException
     */
    public void ensureCanAuthenticate() {
        switch (status) {
            case LOCKED -> throw new UserLockedException("User " + username.value() + " is locked");
            case DISABLED -> throw new UserDisabledException("User " + username.value() + " is disabled");
            case DELETED -> throw new UserDeletedException("User " + username.value() + " is deleted");
            default -> {
                /* ACTIVE */ }
        }
    }

    /**
     * Verifies a password and throws the appropriate domain exception if invalid.
     * Used in login flows.
     */
    public void verifyPassword(String rawPassword, PasswordHasher hasher) {
        ensureCanAuthenticate();
        if (!hasher.matches(rawPassword, passwordHash.value())) {
            throw new com.lanny.spring_security_template.domain.exception.InvalidCredentialsException(
                    "Invalid password for " + username.value());
        }
    }

    // ======================================================
    // INTERNAL SANITIZATION
    // ======================================================

    private static List<String> sanitize(List<String> list) {
        Objects.requireNonNull(list);
        return list.stream()
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .toList();
    }

    // ======================================================
    // GETTERS (IMMUTABLE)
    // ======================================================

    public UserId id() {
        return id;
    }

    public Username username() {
        return username;
    }

    public EmailAddress email() {
        return email;
    }

    public PasswordHash passwordHash() {
        return passwordHash;
    }

    public UserStatus status() {
        return status;
    }

    public List<String> roles() {
        return roles;
    }

    public List<String> scopes() {
        return scopes;
    }

    // ======================================================
    // IDENTITY
    // ======================================================

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof User user))
            return false;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    /**
     * Returns a new {@link User} instance with an updated password hash,
     * preserving all other attributes.
     *
     * <p>
     * This method respects the immutability of the aggregate and is
     * the canonical way to perform password updates from the domain layer.
     * </p>
     *
     * @param newPasswordHash the newly hashed password
     * @return a new {@link User} instance with updated password
     */
    public User withChangedPassword(PasswordHash newPasswordHash) {
        Objects.requireNonNull(newPasswordHash, "PasswordHash cannot be null");
        return new User(
                this.id,
                this.username,
                this.email,
                newPasswordHash,
                this.status,
                this.roles,
                this.scopes);
    }

}
