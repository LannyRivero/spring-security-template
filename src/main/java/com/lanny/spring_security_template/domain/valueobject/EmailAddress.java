package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;

public final class EmailAddress {

    private final String value;

    private EmailAddress(String value) {
        this.value = value;
    }

    public static EmailAddress of(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("Email cannot be null or blank");
        }
        String normalized = raw.trim().toLowerCase();
        if (!normalized.contains("@")) {
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
        if (!(obj instanceof EmailAddress))
            return false;
        EmailAddress other = (EmailAddress) obj;
        return Objects.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
