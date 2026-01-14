package com.lanny.spring_security_template.infrastructure.persistence.jpa.entity;

import java.util.HashSet;
import java.util.Set;

import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.Table;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * ============================================================
 * UserEntity
 * ============================================================
 *
 * <p>
 * Persistence entity representing an authenticated system user.
 * </p>
 *
 * <h2>Security model</h2>
 * <ul>
 * <li>User is a security aggregate root</li>
 * <li>Roles drive authorization via {@code ScopePolicy}</li>
 * <li>Scopes are never assigned directly</li>
 * </ul>
 *
 * <h2>Design decisions</h2>
 * <ul>
 * <li>No public setters</li>
 * <li>Explicit mutation methods</li>
 * <li>Lazy-loaded associations</li>
 * <li>Strong invariants</li>
 * </ul>
 */
@Entity
@Table(name = "users")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(length = 36, updatable = false)
    private String id;

    @Column(unique = true, nullable = false, length = 100, updatable = false)
    private String username;

    @Column(unique = true, nullable = false, length = 150, updatable = false)
    private String email;

    @Column(nullable = false)
    private String passwordHash;

    @Column(nullable = false)
    private boolean enabled = true;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "user_roles", joinColumns = @JoinColumn(name = "user_id"), inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<RoleEntity> roles = new HashSet<>();

    // ======================================================
    // Constructors
    // ======================================================

    public UserEntity(String username, String email, String passwordHash) {
        this.username = require(username, "username");
        this.email = require(email, "email");
        this.passwordHash = require(passwordHash, "passwordHash");
        this.enabled = true;
    }

    // ======================================================
    // Commands (explicit mutations)
    // ======================================================

    public void changePassword(String newHash) {
        this.passwordHash = require(newHash, "passwordHash");
    }

    public void enable() {
        this.enabled = true;
    }

    public void disable() {
        this.enabled = false;
    }

    public UserEntity updateFromDomain(User domain) {
        if (domain.status() == UserStatus.ACTIVE) {
            enable();
        } else {
            disable();
        }
        changePassword(domain.passwordHash().value());
        return this;
    }

    private static String require(String v, String name) {
        if (v == null || v.isBlank()) {
            throw new IllegalArgumentException(name + " must not be blank");
        }
        return v;
    }
}
