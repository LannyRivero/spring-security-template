package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;
import java.util.regex.Pattern;

import com.lanny.spring_security_template.domain.exception.InvalidUsernameException;

/**
 * Value Object representing a normalized, validated username.
 */
public final class Username {

    private static final int MIN_LENGTH = 3;
    private static final int MAX_LENGTH = 50;

    /**
     * Allowed characters: letters, numbers, dot, underscore, hyphen.
     */
    private static final Pattern VALID_PATTERN = Pattern.compile("^[a-zA-Z0-9._-]+$");

    private final String value;

    private Username(String raw) {
        Objects.requireNonNull(raw, "Username cannot be null");

        String normalized = raw.trim().toLowerCase();

        if (normalized.length() < MIN_LENGTH || normalized.length() > MAX_LENGTH) {
            throw new InvalidUsernameException(
                    "Username must be between " + MIN_LENGTH + " and " + MAX_LENGTH + " characters");
        }

        if (!VALID_PATTERN.matcher(normalized).matches()) {
            throw new InvalidUsernameException(
                    "Username contains invalid characters. Allowed: letters, numbers, '.', '_', '-'");
        }

        if (normalized.startsWith(".") || normalized.endsWith(".") || normalized.contains("..")) {
            throw new InvalidUsernameException(
                    "Username cannot start/end with '.' or contain consecutive dots");
        }

        this.value = normalized;
    }

    public static Username of(String raw) {
        return new Username(raw);
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
        if (!(obj instanceof Username other))
            return false;
        return Objects.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
