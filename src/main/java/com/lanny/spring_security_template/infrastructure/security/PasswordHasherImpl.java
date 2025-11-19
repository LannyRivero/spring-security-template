package com.lanny.spring_security_template.infrastructure.security;

import com.lanny.spring_security_template.domain.service.PasswordHasher;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Infra-level implementation of PasswordHasher using Spring Security's
 * PasswordEncoder.
 */
@Component
public class PasswordHasherImpl implements PasswordHasher {

    private final PasswordEncoder encoder;

    public PasswordHasherImpl(PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    @Override
    public String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    @Override
    public boolean matches(String rawPassword, String hashedPassword) {
        return encoder.matches(rawPassword, hashedPassword);
    }
}
