package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;

import lombok.RequiredArgsConstructor;

/**
 * Pure use-case logic for registering a new developer seed user.
 *
 * No logging, no MDC, no auditing.
 * Cross-cutting concerns live in AuthUseCaseLoggingDecorator.
 */
@RequiredArgsConstructor
public class DevRegisterService {

    private final UserAccountGateway userAccountGateway;
    private final PasswordHasher passwordHasher;
    private final AuthMetricsService metrics;
    private final PasswordPolicy passwordPolicy;

    public void register(RegisterCommand cmd) {

        // Validate password
        passwordPolicy.validate(cmd.rawPassword());

        // Hash password
        PasswordHash hash = PasswordHash.of(passwordHasher.hash(cmd.rawPassword()));

        // Create domain user
        User newUser = User.createNew(
                Username.of(cmd.username()),
                EmailAddress.of(cmd.email()),
                hash,
                cmd.roles(),
                cmd.scopes());

        // Persist user and record metrics
        userAccountGateway.save(newUser);
        metrics.recordUserRegistration();
    }
}


