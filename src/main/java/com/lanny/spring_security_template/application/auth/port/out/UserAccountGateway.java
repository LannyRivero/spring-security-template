package com.lanny.spring_security_template.application.auth.port.out;

import com.lanny.spring_security_template.domain.model.User;
import java.util.Optional;

public interface UserAccountGateway {

    Optional<User> findByUsernameOrEmail(String usernameOrEmail);

    void save(User user);
}

