package com.lanny.spring_security_template.domain.model;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * 🔐 Value Object que representa un permiso granular dentro del dominio.
 * 
 * Ejemplo de formato: {@code simulation:read}, {@code user:update}.
 *
 * <p>
 * Un {@link Scope} es inmutable y siempre válido según el patrón
 * {@code resource:action}, garantizando consistencia semántica en todo el
 * sistema.
 * </p>
 */
public final class Scope {

    private static final Pattern VALID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+$");

    private final String name;

    private Scope(String name) {
        if (!isValid(name)) {
            throw new IllegalArgumentException(
                    "Invalid scope format. Must match pattern 'resource:action', e.g. 'user:read'");
        }
        this.name = name;
    }

    /**
     * Fábrica estática para construir un Scope válido.
     *
     * @param name nombre del scope (ej. "profile:read")
     * @return instancia inmutable de Scope
     * @throws IllegalArgumentException si el formato es inválido
     */
    public static Scope of(String name) {
        return new Scope(name);
    }

    /**
     * Valida si un nombre de scope cumple el formato esperado
     * {@code resource:action}.
     *
     * @param name nombre del scope
     * @return true si es válido, false en caso contrario
     */
    public static boolean isValid(String name) {
        return name != null && VALID_PATTERN.matcher(name).matches();
    }

    /**
     * Devuelve el nombre completo del scope.
     */
    public String getName() {
        return name;
    }

    // --- Constantes de ejemplo (base de la plantilla) ---
    public static final Scope PROFILE_READ = Scope.of("profile:read");
    public static final Scope PROFILE_WRITE = Scope.of("profile:write");

    // --- Métodos de igualdad por valor ---
    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (!(o instanceof Scope scope))
            return false;
        return name.equals(scope.name);
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
