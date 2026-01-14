package com.lanny.spring_security_template.domain.valueobject;

import java.util.UUID;

import org.springframework.lang.NonNull;

/**
 * Value Object representing a strongly-typed user identifier.
 *
 * <p>
 * Contract:
 * <ul>
 * <li>Never holds a null value</li>
 * <li>Immutable</li>
 * <li>Safe to expose as String via {@link #toString()}</li>
 * </ul>
 * </p>
 */
public record UserId(@NonNull UUID value) {

    public UserId {
        if (value == null) {
            throw new IllegalArgumentException("UserId value cannot be null");
        }
    }

    public static @NonNull UserId from(@NonNull String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("UserId raw value cannot be null/blank");
        }
        return new UserId(UUID.fromString(raw));
    }

    public static @NonNull UserId newId() {
        return new UserId(UUID.randomUUID());
    }

    /**
     * Explicit accessor to make nullability visible to analysis tools.
     */
    @Override
    public @NonNull UUID value() {
        return value;
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
