package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.domain.service.PasswordHasher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

@Component
public class PasswordHasherImpl implements PasswordHasher {

    private final PasswordEncoder encoder;

    public PasswordHasherImpl(PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return encoder.matches(rawPassword, encodedPassword);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return encoder.encode(rawPassword);
    }
}
