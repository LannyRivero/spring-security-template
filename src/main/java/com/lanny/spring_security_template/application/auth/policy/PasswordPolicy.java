package com.lanny.spring_security_template.application.auth.policy;

/**
 * Defines the password strength policy for user accounts.
 *
 * <p>
 * Implementations of this interface enforce specific complexity
 * rules such as minimum length, character variety, and forbidden patterns.
 * </p>
 *
 * <p>
 * The policy applies at the time of registration or password update
 * and should comply with OWASP ASVS 2.1.7 recommendations.
 * </p>
 *
 * <p>
 * Example usage:
 * <pre>
 * passwordPolicy.validate(command.rawPassword());
 * </pre>
 * </p>
 */
public interface PasswordPolicy {

    /**
     * Validates the provided raw password against the defined complexity rules.
     *
     * @param rawPassword the plaintext password to validate
     * @throws IllegalArgumentException if the password does not meet the requirements
     */
    void validate(String rawPassword);
}

