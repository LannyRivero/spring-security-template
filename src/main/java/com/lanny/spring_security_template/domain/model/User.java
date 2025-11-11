package com.lanny.spring_security_template.domain.model;

import java.util.List;
import java.util.Objects;

import org.springframework.security.crypto.password.PasswordEncoder;

import com.lanny.spring_security_template.domain.exception.UserDeletedException;
import com.lanny.spring_security_template.domain.exception.UserDisabledException;
import com.lanny.spring_security_template.domain.model.exception.UserLockedException;

/**
 * Domain aggregate representing an authenticated user.
 * Extended version supporting multiple status values.
 */
public class User {

    private final String id;
    private final String username;
    private final String email;
    private final String passwordHash;
    private final UserStatus status; // 👈 reemplaza el boolean enabled
    private final List<String> roles;
    private final List<String> scopes;

    public User(String id, String username, String email, String passwordHash,
                UserStatus status, List<String> roles, List<String> scopes) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.status = status;
        this.roles = List.copyOf(roles);
        this.scopes = List.copyOf(scopes);
    }

    /** Domain rule enforcing account policy before authentication */
    public void ensureCanAuthenticate() {
        switch (status) {
            case LOCKED -> throw new UserLockedException("User " + username + " is locked");
            case DISABLED -> throw new UserDisabledException("User " + username + " is disabled");
            case DELETED -> throw new UserDeletedException("User " + username + " is deleted");
            default -> { /* ACTIVE: allowed */ }
        }
    }

    public boolean passwordMatches(String rawPassword, PasswordEncoder encoder) {
        ensureCanAuthenticate();
        return encoder.matches(rawPassword, passwordHash);
    }

    // --- Getters ---
    public String id() { return id; }
    public String username() { return username; }
    public String email() { return email; }
    public UserStatus status() { return status; }
    public List<String> roles() { return roles; }
    public List<String> scopes() { return scopes; }
    public String passwordHash() { return passwordHash; }

    // --- Equality ---
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

