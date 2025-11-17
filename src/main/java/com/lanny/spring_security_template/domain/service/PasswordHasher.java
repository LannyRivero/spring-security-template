package com.lanny.spring_security_template.domain.service;

public interface PasswordHasher {

    boolean matches(CharSequence rawPassword, String encodedPassword);

    String encode(CharSequence rawPassword);
}
