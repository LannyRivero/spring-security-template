package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;
import java.util.regex.Pattern;

/**
 * Value Object representing a validated, normalized email address.
 *
 * <p>
 * Emails are always:
 * </p>
 * <ul>
 * <li>Trimmed</li>
 * <li>Stored in lowercase</li>
 * <li>Validated with a safe and reasonable email pattern</li>
 * <li>Immutable</li>
 * </ul>
 *
 * <p>
 * This VO does not aim to fully validate RFC-5322 emails, but instead
 * enforces a practical and secure subset suitable for authentication systems.
 * </p>
 */
public final class EmailAddress {

    /**
     * Reasonable and safe validation pattern.
     * 
     * Allowed:
     * - Letters, digits, dot, underscore, dash in local-part
     * - Standard domain with at least one dot
     */
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");

    private static final int MAX_LENGTH = 254; // RFC recommendation

    private final String value;

    private EmailAddress(String normalized) {
        this.value = normalized;
    }

    public static EmailAddress of(String raw) {
        Objects.requireNonNull(raw, "Email cannot be null or blank");

        String normalized = raw.trim().toLowerCase();

        if (normalized.isBlank()) {
            throw new IllegalArgumentException("Email cannot be blank");
        }

        if (normalized.length() > MAX_LENGTH) {
            throw new IllegalArgumentException("Email is too long (max 254 chars)");
        }

        if (!EMAIL_PATTERN.matcher(normalized).matches()) {
            throw new IllegalArgumentException("Invalid email format");
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
