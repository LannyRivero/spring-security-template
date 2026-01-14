package com.lanny.spring_security_template.domain.model;

import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.HashSet;

import com.lanny.spring_security_template.domain.exception.UserDeletedException;
import com.lanny.spring_security_template.domain.exception.UserDisabledException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.policy.ScopePolicy;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.UserId;
import com.lanny.spring_security_template.domain.valueobject.Username;

/**
 * Aggregate Root representing a system user.
 *
 * All authentication rules, password checks, and account state
 * validations live here.
 */
public final class User {

    private final UserId id;
    private final Username username;
    private final EmailAddress email;
    private final PasswordHash passwordHash;
    private final UserStatus status;

    /** Value Objects — not strings */
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

    // ======================================================
    // FACTORIES
    // ======================================================

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
            List<Role> roles) {
        return new User(
                id,
                username,
                email,
                passwordHash,
                status,
                sanitizeRoles(roles),
                List.of() // scopes NO persistidas
        );
    }

    // ======================================================
    // DOMAIN RULES
    // ======================================================

    /**
     * Ensures the user is allowed to authenticate based on account status.
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
     * Validates password using domain rules.
     */
    public void verifyPassword(String rawPassword, PasswordHasher hasher) {
        ensureCanAuthenticate();
        if (!hasher.matches(rawPassword, passwordHash.value())) {
            throw new InvalidCredentialsException("Invalid password for " + username.value());
        }
    }

    // ======================================================
    // AUTHORITIES (DERIVED STATE)
    // ======================================================

    /**
     * Simple authority resolution:
     * - ROLE_...
     * - SCOPE_xxx:yyy
     */
    public Set<String> authorities() {
        Set<String> result = new HashSet<>();

        roles.forEach(r -> result.add(r.name()));
        scopes.forEach(s -> result.add("SCOPE_" + s.name()));

        return Set.copyOf(result);
    }

    /**
     * Authority resolution using a Policy (RBAC / ABAC).
     * This is used when roles imply extra scopes dynamically.
     */
    public Set<String> authorities(ScopePolicy policy) {
        Set<String> result = new HashSet<>();

        // roles directos
        roles.forEach(r -> result.add(r.name()));

        // scopes derivados por política
        policy.resolveScopes(Set.copyOf(roles))
                .forEach(s -> result.add("SCOPE_" + s.name()));

        return Set.copyOf(result);
    }

    // ======================================================
    // SANITIZATION HELPERS
    // ======================================================

    private static List<Role> sanitizeRoles(List<Role> list) {
        Objects.requireNonNull(list);
        return list.stream().filter(Objects::nonNull).toList();
    }

    private static List<Scope> sanitizeScopes(List<Scope> list) {
        Objects.requireNonNull(list);
        return list.stream().filter(Objects::nonNull).toList();
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
    // PASSWORD UPDATE (IMMUTABLE)
    // ======================================================

    public User withChangedPassword(PasswordHash newHash) {
        return new User(
                this.id,
                this.username,
                this.email,
                newHash,
                this.status,
                this.roles,
                this.scopes);
    }

    // ======================================================
    // IDENTITY
    // ======================================================

    @Override
    public boolean equals(Object o) {
        return (this == o) ||
                (o instanceof User other && Objects.equals(this.id, other.id));
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}
