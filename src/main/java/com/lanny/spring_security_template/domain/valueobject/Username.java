package com.lanny.spring_security_template.domain.valueobject;

import java.util.Objects;

public final class Username {

    private final String value;

    private Username(String value) {
        this.value = value;
    }

    public static Username of(String raw) {
        if (raw == null || raw.isBlank()) {
            throw new IllegalArgumentException("Username cannot be null or blank");
        }
        return new Username(raw.trim().toLowerCase());
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
        if (!(obj instanceof Username))
            return false;
        Username other = (Username) obj;
        return Objects.equals(value, other.value);
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }
}
