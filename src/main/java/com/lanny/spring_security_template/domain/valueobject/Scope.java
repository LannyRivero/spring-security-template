package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value Object representing a granular permission in the form
 * "resource:action".
 *
 * Examples:
 * - "user:read"
 * - "simulation:update"
 */
public record Scope(String name, String resource, String action) {

    private static final Pattern VALID_PATTERN = Pattern.compile("^[a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+$");

    // Canonical constructor (full constructor, allows parsing safely)
    public Scope(String name, String resource, String action) {
        Objects.requireNonNull(name, "Scope name cannot be null");

        if (!VALID_PATTERN.matcher(name).matches()) {
            throw new IllegalArgumentException(
                    "Invalid scope format. Must be 'resource:action', e.g. 'user:read'");
        }

        String[] parts = name.split(":");

        this.name = name;
        this.resource = parts[0];
        this.action = parts[1];
    }

    /** Factory method */
    public static Scope of(String name) {
        return new Scope(name, null, null);
    }

    /** Static convenience constants */
    public static final Scope PROFILE_READ = Scope.of("profile:read");
    public static final Scope PROFILE_WRITE = Scope.of("profile:write");

    @Override
    public String toString() {
        return name;
    }
}
