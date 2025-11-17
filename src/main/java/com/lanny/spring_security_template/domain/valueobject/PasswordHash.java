package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;

public final class PasswordHash {

    private final String value;

    private PasswordHash(String value) {
        this.value = value;
    }

    public static PasswordHash of(String hash) {
        if (hash == null || hash.isBlank()) {
            throw new IllegalArgumentException("PasswordHash cannot be null or blank");
        }
        return new PasswordHash(hash);
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
        if (!(obj instanceof PasswordHash))
            return false;
        PasswordHash other = (PasswordHash) obj;
        return Objects.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
