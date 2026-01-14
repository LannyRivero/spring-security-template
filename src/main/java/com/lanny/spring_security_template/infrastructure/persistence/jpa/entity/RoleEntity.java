package com.lanny.spring_security_template.infrastructure.persistence.jpa.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.persistence.UniqueConstraint;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

/**
 * ============================================================
 * RoleEntity
 * ============================================================
 *
 * <p>
 * Persistence entity representing a <b>security role</b> used
 * for authorization decisions.
 * </p>
 *
 * <p>
 * A role is a <b>system-level constant</b>:
 * <ul>
 * <li>It is uniquely identified by its {@code name}</li>
 * <li>It must not change once created</li>
 * <li>It is typically assigned to users, not edited dynamically</li>
 * </ul>
 * </p>
 *
 * <h2>Design decisions</h2>
 * <ul>
 * <li>No bidirectional navigation to users</li>
 * <li>No public setters (immutability)</li>
 * <li>Suitable for RBAC and scope-based authorization</li>
 * </ul>
 */
@Entity
@Table(name = "roles", uniqueConstraints = {
        @UniqueConstraint(name = "uk_role_name", columnNames = "name")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class RoleEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Unique role name (e.g. {@code ROLE_ADMIN}, {@code ROLE_USER}).
     */
    @Column(nullable = false, updatable = false)
    private String name;

    /**
     * Creates a new immutable role.
     *
     * <p>
     * This constructor should be used only during
     * bootstrap or controlled administrative setup.
     * </p>
     */
    public RoleEntity(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Role name must not be blank");
        }
        this.name = name;
    }
}
