package com.lanny.spring_security_template.domain.exception;

/**
 * 📕 Domain exception representing a user account that is locked or disabled.
 * 
 * This is part of the domain model — thrown when the aggregate root (User)
 * detects that an operation cannot proceed because the account is not active.
 */
public class UserLockedException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    public UserLockedException(String username) {
        super("User account is locked or disabled: " + username);
    }
}
