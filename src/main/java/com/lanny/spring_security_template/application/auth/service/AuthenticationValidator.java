package com.lanny.spring_security_template.application.auth.service;

import com.lanny.spring_security_template.application.auth.command.LoginCommand;
import com.lanny.spring_security_template.application.auth.port.out.UserAccountGateway;
import com.lanny.spring_security_template.domain.exception.InvalidCredentialsException;
import com.lanny.spring_security_template.domain.model.User;
import com.lanny.spring_security_template.domain.service.PasswordHasher;

import lombok.RequiredArgsConstructor;

/**
 * <h1>AuthenticationValidator</h1>
 *
 * <p>
 * Pure application-layer component responsible for validating user login
 * credentials.
 * It performs <b>all business validation related to user identity</b> without
 * introducing any infrastructure or cross-cutting concerns.
 * </p>
 *
 * <hr>
 *
 * <h2>🔥 Responsibilities</h2>
 *
 * <ul>
 * <li>Retrieve a user by username or email using
 * {@link UserAccountGateway}</li>
 * <li>Ensure the user is allowed to authenticate (not locked, disabled,
 * etc.)</li>
 * <li>Verify password integrity using {@link PasswordHasher}</li>
 * <li>Fail securely using generic exceptions to prevent user enumeration</li>
 * </ul>
 *
 * <p>
 * This class intentionally contains <b>NO</b>:
 * </p>
 * <ul>
 * <li>Logging</li>
 * <li>MDC trace management</li>
 * <li>AUDIT events</li>
 * <li>Framework annotations (@Service, @Transactional, etc.)</li>
 * </ul>
 *
 * These concerns are handled at higher layers such as:
 * <ul>
 * <li>{@link com.lanny.spring_security_template.application.auth.service.AuthUseCaseLoggingDecorator}</li>
 * <li>Transactional adapters in the infrastructure layer</li>
 * </ul>
 *
 * <hr>
 *
 * <h2>🔐 Security & OWASP ASVS Alignment</h2>
 *
 * <ul>
 * <li><b>ASVS 2.1.1</b> – Authentication must not reveal valid usernames.</li>
 * <li><b>ASVS 2.1.4</b> – Enforce account state checks (locked, disabled,
 * expired).</li>
 * <li><b>ASVS 2.2.1</b> – Password verification must use secure hashing.</li>
 * <li><b>ASVS 2.2.4</b> – Authentication logic must be centralized and
 * consistent.</li>
 * </ul>
 *
 * <hr>
 *
 * <h2>🏛 Architectural Role (Clean Architecture – Application Layer)</h2>
 *
 * <pre>
 *   [Domain] ← user entity, password value objects
 *        ↑
 *   [Application] ← AuthenticationValidator (this class)
 *        ↑
 *   [Interface/Adapters] ← Controllers, Decorators, Transactional Adapters
 * </pre>
 *
 * This validator isolates <b>core authentication rules</b> so they can be
 * reused
 * across use cases such as:
 *
 * <ul>
 * <li>User login</li>
 * <li>Token refresh with password re-validation</li>
 * <li>Privileged actions requiring password confirmation</li>
 * </ul>
 *
 * <hr>
 *
 * <h2>⚙ Method Workflow</h2>
 *
 * <ol>
 * <li>Extract username/email from {@link LoginCommand}</li>
 * <li>Load user using {@link UserAccountGateway}</li>
 * <li>Throw <b>generic error</b> if not found → prevents enumeration</li>
 * <li>Verify user account state via {@link User#ensureCanAuthenticate()}</li>
 * <li>Compare password using secure hashing</li>
 * <li>Return authenticated {@link User} entity to upper layers</li>
 * </ol>
 *
 * <hr>
 *
 * <h2>💡 Design Notes</h2>
 *
 * <ul>
 * <li>Stateless and fully testable</li>
 * <li>Respects SRP: contains only validation logic</li>
 * <li>Easy to mock in higher-level unit tests</li>
 * <li>Extensible for MFA or additional validation steps</li>
 * </ul>
 *
 * <hr>
 *
 * <h2>📌 Usage Example</h2>
 *
 * <pre>{@code
 * AuthenticationValidator validator = ...
 * User user = validator.validate(new LoginCommand("alice", "secret"));
 * }</pre>
 */
@RequiredArgsConstructor
public class AuthenticationValidator {

    private final UserAccountGateway userAccountGateway;
    private final PasswordHasher passwordHasher;

    /**
     * Validates a user's credentials based on business authentication rules.
     *
     * <p>
     * The method intentionally returns the fully loaded {@link User} entity,
     * allowing upper layers (e.g., token creation services) to extract roles,
     * scopes, and other attributes.
     * </p>
     *
     * @param cmd the login command containing username/email + password
     * @return the authenticated {@link User} if credentials are valid
     * @throws InvalidCredentialsException
     *                                     if the username does not exist, the
     *                                     account cannot authenticate,
     *                                     or the password is incorrect (generic to
     *                                     prevent enumeration)
     */
    public User validate(LoginCommand cmd) {
        String username = cmd.username();

        // 1. Retrieve user (generic error → avoids enumeration)
        User user = userAccountGateway.findByUsernameOrEmail(username)
                .orElseThrow(() -> new InvalidCredentialsException("Invalid username or password"));

        // 2. Validate user account state
        user.ensureCanAuthenticate();

        // 3. Validate password integrity
        if (!passwordHasher.matches(cmd.password(), user.passwordHash().value())) {
            throw new InvalidCredentialsException("Invalid username or password");
        }

        return user;
    }
}
