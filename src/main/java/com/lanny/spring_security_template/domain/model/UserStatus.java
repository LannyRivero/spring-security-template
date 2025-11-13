package com.lanny.spring_security_template.domain.model;

/**
 *  Enum que representa el estado del usuario dentro del sistema.
 *
 * <p>
 * El estado de un usuario controla si puede autenticarse y acceder
 * a recursos protegidos.
 * </p>
 *
 * <p>
 * Generalmente, se utiliza junto con {@code UserAccountGateway}
 * y la lógica de autenticación del dominio.
 * </p>
 */
public enum UserStatus {

    /** Usuario activo y con acceso permitido. */
    ACTIVE,

    /** Usuario bloqueado temporalmente (intentos fallidos, política, etc.). */
    LOCKED,

    /** Usuario deshabilitado por un administrador. */
    DISABLED,

    /** Usuario eliminado lógicamente (soft delete). */
    DELETED;

    /**
     * Indica si el usuario está en estado activo.
     */
    public boolean isActive() {
        return this == ACTIVE;
    }

    /**
     * Indica si el usuario puede autenticarse (login).
     * Bloquea a los usuarios con estados no válidos.
     */
    public boolean canLogin() {
        return this == ACTIVE;
    }

    /**
     * Indica si el usuario ha sido deshabilitado de forma permanente.
     */
    public boolean isDisabled() {
        return this == DISABLED || this == DELETED;
    }

    /**
     * Indica si el usuario fue bloqueado temporalmente.
     */
    public boolean isLocked() {
        return this == LOCKED;
    }
}
