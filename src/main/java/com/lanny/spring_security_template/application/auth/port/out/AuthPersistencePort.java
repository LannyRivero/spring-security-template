package com.lanny.spring_security_template.application.auth.port.out;

import java.util.Optional;

import com.lanny.spring_security_template.domain.model.User;

public interface AuthPersistencePort {
    Optional<User> findByUsername(String username);
}