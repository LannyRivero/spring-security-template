package com.lanny.spring_security_template.infrastructure.persistence.jpa.repository;

import com.lanny.spring_security_template.infrastructure.persistence.jpa.entity.UserEntity;

class UserTestData {

    static final String USERNAME = "john_doe";
    static final String USERNAME_UPPER = "JOHN_DOE";
    static final String EMAIL = "john@example.com";
    static final String EMAIL_UPPER = "JOHN@EXAMPLE.COM";

    static UserEntity defaultUser() {
        UserEntity user = new UserEntity();
        user.setUsername(USERNAME);
        user.setEmail(EMAIL);
        user.setPasswordHash("hashedPassword123");
        user.setEnabled(true);
        return user;
    }
}
