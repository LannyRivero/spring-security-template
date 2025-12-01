package com.lanny.spring_security_template.domain.model;

import java.util.List;
import java.util.Objects;

import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.exception.UserDeletedException;
import com.lanny.spring_security_template.domain.exception.UserDisabledException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.UserId;
import com.lanny.spring_security_template.domain.valueobject.Username;

public final class User {

    private final UserId id;
    private final Username username;
    private final EmailAddress email;
    private final PasswordHash passwordHash;
    private final UserStatus status;
    private final List<Role> roles;
    private final List<Scope> scopes;

    private User(
            UserId id,
            Username username,
            EmailAddress email,
            PasswordHash passwordHash,
            UserStatus status,
            List<Role> roles,
            List<Scope> scopes) {

        this.id = Objects.requireNonNull(id);
        this.username = Objects.requireNonNull(username);
        this.email = Objects.requireNonNull(email);
        this.passwordHash = Objects.requireNonNull(passwordHash);
        this.status = Objects.requireNonNull(status);
        this.roles = List.copyOf(roles);
        this.scopes = List.copyOf(scopes);
    }

    public static User createNew(
            Username username,
            EmailAddress email,
            PasswordHash passwordHash,
            List<Role> roles,
            List<Scope> scopes) {

        return new User(
                UserId.newId(),
                username,
                email,
                passwordHash,
                UserStatus.ACTIVE,
                sanitizeRoles(roles),
                sanitizeScopes(scopes));
    }

    public static User rehydrate(
            UserId id,
            Username username,
            EmailAddress email,
            PasswordHash passwordHash,
            UserStatus status,
            List<Role> roles,
            List<Scope> scopes) {

        return new User(
                id,
                username,
                email,
                passwordHash,
                status,
                sanitizeRoles(roles),
                sanitizeScopes(scopes));
    }

    // ======================================================
    // DOMAIN RULES
    // ======================================================

    public void ensureCanAuthenticate() {
        switch (status) {
            case LOCKED -> throw new UserLockedException();
            case DISABLED -> throw new UserDisabledException();
            case DELETED -> throw new UserDeletedException();
            default -> {
                /* ACTIVE */ }
        }
    }

    public void verifyPassword(String rawPassword, PasswordHasher hasher) {
        ensureCanAuthenticate();

        if (!hasher.matches(rawPassword, passwordHash.value())) {
            throw new InvalidCredentialsException();
        }
    }

    // ======================================================
    // SANITIZATION
    // ======================================================

    private static List<Role> sanitizeRoles(List<Role> list) {
        Objects.requireNonNull(list);
        return list.stream()
                .filter(Objects::nonNull)
                .toList();
    }

    private static List<Scope> sanitizeScopes(List<Scope> list) {
        Objects.requireNonNull(list);
        return list.stream()
                .filter(Objects::nonNull)
                .toList();
    }

    // ======================================================
    // IMMUTABLE GETTERS
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

    public List<Role> roles() {
        return roles;
    }

    public List<Scope> scopes() {
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

    // ======================================================
    // PASSWORD CHANGE
    // ======================================================

    public User withChangedPassword(PasswordHash newPasswordHash) {
        Objects.requireNonNull(newPasswordHash);
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
