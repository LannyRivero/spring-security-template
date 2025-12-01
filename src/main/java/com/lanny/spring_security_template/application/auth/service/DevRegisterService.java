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
 * Application-level use case responsible for registering a new developer seed
 * user.
 *
 * <p>
 * This service contains <strong>pure business logic only</strong>.
 * It does NOT perform:
 * <ul>
 * <li>logging</li>
 * <li>MDC (Mapped Diagnostic Context)</li>
 * <li>auditing</li>
 * <li>transaction management</li>
 * <li>framework-specific concerns</li>
 * </ul>
 * All cross-cutting concerns are explicitly delegated to infrastructure-layer
 * decorators (e.g., {@code AuthUseCaseLoggingDecorator}) and transactional
 * adapters.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Validate the raw password using {@link PasswordPolicy}</li>
 * <li>Hash the password using {@link PasswordHasher}</li>
 * <li>Create a new {@link User} aggregate according to domain rules</li>
 * <li>Persist the new user via {@link UserAccountGateway}</li>
 * <li>Record registration metrics via {@link AuthMetricsService}</li>
 * </ul>
 *
 * <h2>Why this class is framework-agnostic?</h2>
 * <p>
 * The service lives in the <strong>Application Layer</strong> and follows the
 * dependency rule: it depends only on domain models and application ports,
 * never on infrastructure or Spring Boot. This ensures deterministic unit tests
 * and long-term maintainability.
 * </p>
 *
 * <h2>Security Compliance</h2>
 * <ul>
 * <li>OWASP ASVS 2.1.1 – Enforce strong password policies</li>
 * <li>OWASP ASVS 2.2.2 – Ensure credentials are securely hashed</li>
 * <li>OWASP ASVS 2.10 – Ensure authentication actions are auditable
 * (auditing is handled externally, not here)</li>
 * </ul>
 *
 * <h2>Typical Flow</h2>
 * 
 * <pre>{@code
 * passwordPolicy.validate(rawPassword);
 * hashed = PasswordHash.of(passwordHasher.hash(rawPassword));
 * user = User.createNew(...);
 * userAccountGateway.save(user);
 * metrics.recordUserRegistration();
 * }</pre>
 *
 * @see UserAccountGateway
 * @see PasswordHasher
 * @see PasswordPolicy
 * @see AuthMetricsService
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
