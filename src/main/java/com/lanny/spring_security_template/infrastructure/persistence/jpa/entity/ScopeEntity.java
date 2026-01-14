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
 * ScopeEntity
 * ============================================================
 *
 * <p>
 * Persistence entity representing a <b>fine-grained permission</b>
 * used in authorization decisions.
 * </p>
 *
 * <p>
 * Scopes follow the {@code resource:action} convention
 * (e.g. {@code profile:read}, {@code user:manage}).
 * </p>
 *
 * <h2>Security model</h2>
 * <ul>
 * <li>Scopes are system-level constants</li>
 * <li>They must not change once created</li>
 * <li>They are assigned to users via roles or policies</li>
 * </ul>
 *
 * <h2>Design decisions</h2>
 * <ul>
 * <li>No bidirectional relationship to users</li>
 * <li>No public setters (immutability)</li>
 * <li>Explicit validation at creation time</li>
 * </ul>
 */
@Entity
@Table(name = "scopes", uniqueConstraints = {
        @UniqueConstraint(name = "uk_scope_name", columnNames = "name")
})
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class ScopeEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * Unique scope name following {@code resource:action} format.
     */
    @Column(nullable = false, updatable = false)
    private String name;

    /**
     * Creates a new immutable scope.
     *
     * <p>
     * This constructor should be used only during
     * system bootstrap or controlled administrative setup.
     * </p>
     */
    public ScopeEntity(String name) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Scope name must not be blank");
        }
        if (!name.contains(":")) {
            throw new IllegalArgumentException(
                    "Scope name must follow 'resource:action' format");
        }
        this.name = name;
    }
}
