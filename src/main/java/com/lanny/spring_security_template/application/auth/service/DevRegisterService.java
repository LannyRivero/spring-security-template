package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.model.UserStatus;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;
import com.lanny.spring_security_template.infrastructure.metrics.AuthMetricsService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class DevRegisterService {

    private final UserAccountGateway userAccountGateway;
    private final PasswordHasher passwordHasher;
    private final AuthMetricsService metrics;

    public void register(RegisterCommand cmd) {

        User newUser = new User(
                null,
                Username.of(cmd.username()),
                EmailAddress.of(cmd.email()),
                PasswordHash.of(passwordHasher.hash(cmd.rawPassword())),
                UserStatus.ACTIVE,
                cmd.roles(),
                cmd.scopes());

        userAccountGateway.save(newUser);
        metrics.recordUserRegistration();

        System.out.printf("[DEV] Seed user created: %s%n", newUser.username().value());
    }
}
