package com.lanny.spring_security_template.domain.model;

import java.util.Objects;

/**
 * Value Object representing a fine-grained permission in the format:
 *
 *     resource:action
 *
 * Examples:
 * - simulation:read
 * - simulation:write
 * - users:create
 * - reports:generate
 *
 * Naming rules:
 * - Always lowercase
 * - Must contain exactly one colon
 * - Must match the pattern: ^[a-z0-9_-]+:[a-z0-9_-]+$
 *
 * This design is compatible with modern IAM systems (Google IAM, AWS IAM, Auth0).
 */
public record Scope(String name) {

    private static final String REGEX = "^[a-z0-9_-]+:[a-z0-9_-]+$";

    public Scope {
        Objects.requireNonNull(name, "Scope name cannot be null");

        // Normalize input
        name = name.trim().toLowerCase();

        // Validate scope format
        if (!name.matches(REGEX)) {
            throw new IllegalArgumentException(
                    "Invalid scope '" + name + "'. Expected format resource:action, example: simulation:read");
        }
    }

    /** Parse "users:read" into a Scope instance */
    public static Scope of(String raw) {
        return new Scope(raw);
    }

    /** Returns the resource (left side). */
    public String resource() {
        return name.substring(0, name.indexOf(':'));
    }

    /** Returns the action (right side). */
    public String action() {
        return name.substring(name.indexOf(':') + 1);
    }

    /** Useful constants */
    public static final Scope PROFILE_READ = Scope.of("profile:read");
    public static final Scope PROFILE_WRITE = Scope.of("profile:write");

    @Override
    public String toString() {
        return name;
    }
}
