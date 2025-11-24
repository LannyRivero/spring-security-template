package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value Object representing a normalized, validated username.
 *
 * <p>
 * Usernames are:
 * </p>
 * <ul>
 * <li>Case-insensitive (stored as lowercase)</li>
 * <li>Validated against a safe character set</li>
 * <li>Validated by length constraints</li>
 * <li>Immutable</li>
 * </ul>
 *
 * <p>
 * This class centralizes all username-related rules
 * inside the domain model, ensuring consistency.
 * </p>
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
            throw new IllegalArgumentException(
                    "Username must be between " + MIN_LENGTH + " and " + MAX_LENGTH + " characters");
        }

        if (!VALID_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException(
                    "Username contains invalid characters. Allowed: letters, numbers, '.', '_', '-'");
        }

        this.value = normalized;
    }

    /**
     * Static factory method.
     */
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
