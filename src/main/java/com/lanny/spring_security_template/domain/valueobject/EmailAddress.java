package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;
import java.util.regex.Pattern;

import com.lanny.spring_security_template.domain.exception.InvalidEmailException;

/**
 * Value Object representing a validated, normalized email address.
 */
public final class EmailAddress {

    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private static final int MAX_LENGTH = 254; // RFC recommendation

    private final String value;

    private EmailAddress(String normalized) {
        this.value = normalized;
    }

    public static EmailAddress of(String raw) {
        Objects.requireNonNull(raw, "Email cannot be null");

        String normalized = raw.trim().toLowerCase();

        if (normalized.isBlank()) {
            throw new InvalidEmailException("Email cannot be blank");
        }

        if (normalized.length() > MAX_LENGTH) {
            throw new InvalidEmailException("Email is too long (max 254 chars)");
        }

        if (!EMAIL_PATTERN.matcher(normalized).matches()) {
            throw new InvalidEmailException("Invalid email format");
        }

        return new EmailAddress(normalized);
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
        if (!(obj instanceof EmailAddress other))
            return false;
        return Objects.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
