package com.lanny.spring_security_template.application.auth.service;

import java.time.Instant;

import org.slf4j.MDC;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.lanny.spring_security_template.application.auth.command.RegisterCommand;
import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import com.lanny.spring_security_template.application.auth.port.out.AuditEventPublisher;
import com.lanny.spring_security_template.application.auth.port.out.AuthMetricsService;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.event.SecurityEvent;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;
import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.domain.valueobject.EmailAddress;
import com.lanny.spring_security_template.domain.valueobject.PasswordHash;
import com.lanny.spring_security_template.domain.valueobject.Username;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Registers a new developer seed user.
 *
 * <p>
 * This service is intended for initial bootstrap or testing environments
 * and enforces password policy and audit compliance.
 * </p>
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class DevRegisterService {

    private final UserAccountGateway userAccountGateway;
    private final PasswordHasher passwordHasher;
    private final AuthMetricsService metrics;
    private final PasswordPolicy passwordPolicy;
    private final AuditEventPublisher auditEventPublisher;
    private final ClockProvider clockProvider;

    /**
     * Registers a new developer seed user.
     *
     * @param cmd registration command containing credentials and roles
     */
    @Transactional
    public void register(RegisterCommand cmd) {
        String traceId = MDC.get("traceId");
        Instant now = clockProvider.now();

        log.info("[DEV_REGISTER_REQUEST] user={} trace={} ts={}", cmd.username(), traceId, now);

        // 1️ Validate password strength
        passwordPolicy.validate(cmd.rawPassword());

        // 2️ Hash password
        PasswordHash hash = PasswordHash.of(passwordHasher.hash(cmd.rawPassword()));

        // 3️ Create domain user
        User newUser = User.createNew(
                Username.of(cmd.username()),
                EmailAddress.of(cmd.email()),
                hash,
                cmd.roles(),
                cmd.scopes());

        // 4️ Persist and record metrics
        userAccountGateway.save(newUser);
        metrics.recordUserRegistration();

        // 5️ Audit and log event
        auditEventPublisher.publishAuthEvent(
                SecurityEvent.USER_REGISTERED.name(),
                cmd.username(),
                now,
                "Developer seed user registered successfully");

        log.info("[DEV_REGISTER_SUCCESS] user={} trace={} ts={}", cmd.username(), traceId, now);
        MDC.clear();
    }
}
