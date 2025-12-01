package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;

import com.lanny.spring_security_template.domain.exception.InvalidPasswordHashException;

/**
 * Value Object representing a hashed password.
 */
public final class PasswordHash {

    private static final int MIN_LENGTH = 20; // reasonable for modern hashes

    private final String value;

    private PasswordHash(String value) {
        this.value = value;
    }

    public static PasswordHash of(String hash) {
        Objects.requireNonNull(hash, "PasswordHash cannot be null");

        String cleaned = hash.trim();

        if (cleaned.isBlank()) {
            throw new InvalidPasswordHashException("PasswordHash cannot be blank");
        }

        if (cleaned.contains(" ")) {
            throw new InvalidPasswordHashException("PasswordHash must not contain spaces");
        }

        if (cleaned.length() < MIN_LENGTH) {
            throw new InvalidPasswordHashException("PasswordHash is too short to be a valid hash");
        }

        // Heurística: la mayoría de hashes seguros incluyen metadatos estructurados
        if (!cleaned.startsWith("$")) {
            throw new InvalidPasswordHashException("PasswordHash format appears invalid");
        }

        return new PasswordHash(cleaned);
    }

    public String value() {
        return value;
    }

    @Override
    public String toString() {
        return value;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj)
            return true;
        if (!(obj instanceof PasswordHash other))
            return false;
        return Objects.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
