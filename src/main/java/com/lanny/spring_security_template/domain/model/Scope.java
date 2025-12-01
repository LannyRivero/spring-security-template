package com.lanny.spring_security_template.domain.model;

import java.util.Objects;

import com.lanny.spring_security_template.domain.exception.InvalidScopeException;

/**
 * Value Object representing a fine-grained permission in the format:
 *   resource:action
 */
public record Scope(String name) {

    private static final String REGEX = "^[a-z0-9_-]+:[a-z0-9_-]+$";

    public Scope {
        Objects.requireNonNull(name, "Scope name cannot be null");

        String normalized = name.trim().toLowerCase();

        if (!normalized.matches(REGEX)) {
            throw new InvalidScopeException(
                    "Invalid scope '" + normalized + "'. Expected format resource:action, example: simulation:read");
        }

        name = normalized;
    }

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

    @Override
    public String toString() {
        return name;
    }
}

