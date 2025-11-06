package com.lanny.spring_security_template.domain.model.exception;

public class UserLockedException extends RuntimeException {
    public UserLockedException(String username) {
        super("User " + username + " is locked or disabled.");
    }
}
