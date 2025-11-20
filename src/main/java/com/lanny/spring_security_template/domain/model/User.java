package com.lanny.spring_security_template.domain.model;

import com.lanny.spring_security_template.domain.exception.UserDeletedException;
import com.lanny.spring_security_template.domain.exception.UserDisabledException;
import com.lanny.spring_security_template.domain.exception.UserLockedException;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;

import java.util.List;
import java.util.Objects;

/**
 * Domain aggregate representing an authenticated user.
 * Clean version using Value Objects and without infrastructure dependencies.
 */
public final class User {

    private final String id;
    private final Username username;
    private final EmailAddress email;
    private final PasswordHash passwordHash;
    private final UserStatus status;
    private final List<String> roles;
    private final List<String> scopes;

    public User(
            String id,
            Username username,
            EmailAddress email,
            PasswordHash passwordHash,
            UserStatus status,
            List<String> roles,
            List<String> scopes
    ) {
        this.id = id;
        this.username = Objects.requireNonNull(username);
        this.email = Objects.requireNonNull(email);
        this.passwordHash = Objects.requireNonNull(passwordHash);
        this.status = Objects.requireNonNull(status);
        this.roles = List.copyOf(roles);
        this.scopes = List.copyOf(scopes);
    }

    /** Domain rule enforcing account policy before authentication */
    public void ensureCanAuthenticate() {
        switch (status) {
            case LOCKED -> throw new UserLockedException("User " + username.value() + " is locked");
            case DISABLED -> throw new UserDisabledException("User " + username.value() + " is disabled");
            case DELETED -> throw new UserDeletedException("User " + username.value() + " is deleted");
            default -> { /* ACTIVE: allowed */ }
        }
    }

    /**
     * Delegates password checking to a domain-safe abstraction.
     * This avoids leaking Spring Security into the domain layer.
     */
    public boolean passwordMatches(String rawPassword, PasswordHasher hasher) {
        ensureCanAuthenticate();
        return hasher.matches(rawPassword, this.passwordHash.value());
    }

    // --- Getters ---
    public String id() { return id; }
    public Username username() { return username; }
    public EmailAddress email() { return email; }
    public PasswordHash passwordHash() { return passwordHash; }
    public UserStatus status() { return status; }
    public List<String> roles() { return roles; }
    public List<String> scopes() { return scopes; }

    // --- Equality based on ID ---
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof User user)) return false;
        return Objects.equals(id, user.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }
}


