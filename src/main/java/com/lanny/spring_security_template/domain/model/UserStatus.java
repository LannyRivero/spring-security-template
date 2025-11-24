package com.lanny.spring_security_template.domain.model;

/**
 * Represents all possible lifecycle states of a user account.
 *
 * <p>
 * This enum is part of the core authentication domain model.
 * It controls whether a user can authenticate or access protected resources.
 * </p>
 *
 * <p>
 * Only users in {@link #ACTIVE} state are allowed to authenticate.
 * Other states represent different types of restrictions applied to the
 * account.
 * </p>
 */
public enum UserStatus {

    /**
     * User is active and fully allowed to authenticate and access the system.
     */
    ACTIVE,

    /**
     * User is temporarily locked due to security policies
     * (e.g., too many failed login attempts).
     */
    LOCKED,

    /**
     * User is permanently disabled by an administrator.
     */
    DISABLED,

    /**
     * User has been logically deleted (soft delete).
     * No authentication or access is allowed.
     */
    DELETED;

    // -------------------------------------------------------------------------
    // Convenience domain helpers
    // -------------------------------------------------------------------------

    /**
     * @return {@code true} if the user is in ACTIVE state.
     */
    public boolean isActive() {
        return this == ACTIVE;
    }

    /**
     * @return {@code true} if the user is temporarily locked.
     */
    public boolean isLocked() {
        return this == LOCKED;
    }

    /**
     * @return {@code true} if the user account has been disabled administratively.
     */
    public boolean isDisabled() {
        return this == DISABLED;
    }

    /**
     * @return {@code true} if the user has been logically deleted.
     */
    public boolean isDeleted() {
        return this == DELETED;
    }

    /**
     * Determines whether the user is allowed to authenticate.
     *
     * @return {@code true} only if the user is ACTIVE.
     */
    public boolean canAuthenticate() {
        return this == ACTIVE;
    }

    /**
     * Whether this status represents a terminal, non-recoverable state.
     * Useful for audit logic and data lifecycle policies.
     *
     * @return {@code true} for states where the user cannot be restored.
     */
    public boolean isTerminalState() {
        return this == DELETED;
    }
}
