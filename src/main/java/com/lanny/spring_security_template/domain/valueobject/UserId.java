package com.lanny.spring_security_template.domain.valueobject;

import java.util.UUID;

/**
 * Value Object representing a strongly-typed User identifier.
 *
 * <p>
 * Internally it wraps a UUID but exposes only domain-level semantics.
 * </p>
 */
public record UserId(UUID value) {

    public UserId {
        if (value == null) {
            throw new IllegalArgumentException("UserId value cannot be null");
        }
    }

    /**
     * Create a {@link UserId} from a raw string (typically from persistence).
     */
    public static UserId from(String raw) {
        return new UserId(UUID.fromString(raw));
    }

    /**
     * Generate a brand-new unique UserId.
     * <p>
     * Used in registration flows or when creating new aggregates.
     */
    public static UserId newId() {
        return new UserId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
