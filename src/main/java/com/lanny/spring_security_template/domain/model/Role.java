package com.lanny.spring_security_template.domain.model;

import java.util.Collections;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;

/**
 *  Entidad de dominio que representa un Rol del sistema.
 * 
 * Un {@code Role} agrupa un conjunto de {@link Scope} que definen permisos
 * finos
 * de acceso a recursos dentro del dominio (p. ej. ADMIN, USER, MANAGER, etc.).
 *
 * <p>
 * Ejemplo:
 * </p>
 * 
 * <pre>
 * Role admin = Role.of("ADMIN", Set.of(
 *         Scope.of("user:read"),
 *         Scope.of("user:update"),
 *         Scope.of("simulation:read")));
 * </pre>
 */
public final class Role {

    private final String name;
    private final Set<Scope> scopes;

    private Role(String name, Set<Scope> scopes) {
        if (name == null || name.isBlank()) {
            throw new IllegalArgumentException("Role name cannot be null or blank");
        }
        this.name = name.toUpperCase();
        this.scopes = new HashSet<>(Objects.requireNonNull(scopes, "Scopes cannot be null"));
    }

    /**
     * Fábrica estática para crear roles inmutables.
     *
     * @param name   nombre del rol (ej. "ADMIN")
     * @param scopes conjunto de scopes asociados
     * @return instancia de Role
     */
    public static Role of(String name, Set<Scope> scopes) {
        return new Role(name, scopes);
    }

    /**
     * Nombre único del rol (en mayúsculas).
     */
    public String getName() {
        return name;
    }

    /**
     * Conjunto inmutable de permisos asociados.
     */
    public Set<Scope> getScopes() {
        return Collections.unmodifiableSet(scopes);
    }

    /**
     * Indica si el rol posee un determinado scope.
     */
    public boolean hasScope(Scope scope) {
        return scopes.contains(scope);
    }

    /**
     * Indica si este rol representa un administrador global.
     */
    public boolean isAdmin() {
        return "ADMIN".equalsIgnoreCase(name);
    }

    /**
     * Indica si este rol es interno del sistema (ej: SYSTEM, SERVICE).
     */
    public boolean isSystem() {
        return "SYSTEM".equalsIgnoreCase(name);
    }

    /**
     * Combina este rol con otro, uniendo sus scopes.
     *
     * @param other otro rol
     * @return nuevo Role con scopes fusionados
     */
    public Role mergeWith(Role other) {
        Set<Scope> merged = new HashSet<>(this.scopes);
        merged.addAll(other.scopes);
        return new Role(this.name, merged);
    }

    /**
     * Convierte los scopes del rol a nombres de autoridad (ej:
     * "SCOPE_profile:read").
     */
    public Set<String> toAuthorities() {
        Set<String> authorities = new HashSet<>();
        authorities.add("ROLE_" + name);
        scopes.forEach(scope -> authorities.add("SCOPE_" + scope.getName()));
        return authorities;
    }

    // --- Igualdad por nombre de rol ---
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof Role role))
            return false;
        return name.equals(role.name);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name);
    }

    @Override
    public String toString() {
        return name;
    }
}
