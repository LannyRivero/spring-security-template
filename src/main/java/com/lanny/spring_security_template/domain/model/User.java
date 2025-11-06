package com.lanny.spring_security_template.domain.model;

import java.util.List;
import java.util.Objects;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.lanny.spring_security_template.domain.model.exception.UserLockedException;

/**
 * Domain aggregate representing an authenticated user.
 */
public class User {

    private final String id;
    private final String username;
    private final String email;
    private final String passwordHash;
    private final boolean enabled;
    private final List<String> roles;
    private final List<String> scopes;

    public User(String id, String username, String email, String passwordHash,
            boolean enabled, List<String> roles, List<String> scopes) {
        this.id = id;
        this.username = username;
        this.email = email;
        this.passwordHash = passwordHash;
        this.enabled = enabled;
        this.roles = List.copyOf(roles);
        this.scopes = List.copyOf(scopes);
    }

    public String id() {
        return id;
    }

    public String username() {
        return username;
    }

    public String email() {
        return email;
    }

    public List<String> roles() {
        return roles;
    }

    public List<String> scopes() {
        return scopes;
    }

    public boolean isEnabled() {
        return enabled;
    }

    /** Getter interno (infraestructura puede acceder) */
    public String passwordHash() {
        return passwordHash;
    }

    /** ✅ Dominio controla la validación de contraseñas */
    public boolean passwordMatches(String rawPassword, PasswordEncoder encoder) {
        if (!enabled) {
            throw new UserLockedException(username);
        }
        return encoder.matches(rawPassword, passwordHash);
    }

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
}
