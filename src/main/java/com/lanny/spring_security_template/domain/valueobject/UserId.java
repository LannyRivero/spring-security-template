package com.lanny.spring_security_template.domain.valueobject;

import java.util.UUID;

/**
 * Value Object representing a strongly-typed User identifier.
 */
public record UserId(UUID value) {

    public UserId {
        if (value == null) {
            throw new IllegalArgumentException("UserId value cannot be null");
        }
    }

    public static UserId from(String raw) {
        return new UserId(UUID.fromString(raw));
    }

    public static UserId newId() {
        return new UserId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}

