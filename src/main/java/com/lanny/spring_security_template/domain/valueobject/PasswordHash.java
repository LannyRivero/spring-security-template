package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;

/**
 * Value Object representing a hashed password.
 *
 * <p>
 * This class ensures that:
 * </p>
 * <ul>
 * <li>The password hash is never null or blank</li>
 * <li>The value is already hashed (not raw password)</li>
 * <li>No algorithm-specific logic leaks into the domain</li>
 * <li>Basic safety checks are applied</li>
 * </ul>
 *
 * <p>
 * This VO does <strong>not</strong> enforce a specific hashing algorithm
 * (BCrypt, Argon2, PBKDF2, etc.), keeping the domain free of infrastructure
 * details.
 * </p>
 */
public final class PasswordHash {

    private static final int MIN_LENGTH = 20; // reasonable for modern hashes

    private final String value;

    private PasswordHash(String value) {
        this.value = value;
    }

    /**
     * Creates a new {@link PasswordHash} from a pre-hashed string.
     *
     * @param hash the hashed password (never the raw password)
     * @return a validated and immutable PasswordHash value object
     */
    public static PasswordHash of(String hash) {
        Objects.requireNonNull(hash, "PasswordHash cannot be null");

        String cleaned = hash.trim();

        if (cleaned.isBlank()) {
            throw new IllegalArgumentException("PasswordHash cannot be blank");
        }

        if (cleaned.contains(" ")) {
            throw new IllegalArgumentException("PasswordHash must not contain spaces");
        }

        if (cleaned.length() < MIN_LENGTH) {
            throw new IllegalArgumentException("PasswordHash is too short to be a valid hash");
        }

        // Optional heuristic: many hashing algorithms use prefix '$'
        if (!cleaned.startsWith("$")) {
            // Could be Argon2, PBKDF2, etc. but most use '$'
            // We only warn by enforcing structured format expectations.
            throw new IllegalArgumentException("PasswordHash format appears invalid");
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
