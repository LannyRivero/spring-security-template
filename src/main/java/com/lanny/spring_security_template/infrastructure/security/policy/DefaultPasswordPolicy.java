package com.lanny.spring_security_template.infrastructure.security.policy;

import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;
import org.springframework.stereotype.Component;

import java.util.regex.Pattern;

/**
 * Default implementation of {@link PasswordPolicy} enforcing minimal
 * enterprise-grade password complexity.
 *
 * <p>
 * Rules (configurable via regex):
 * <ul>
 * <li>At least 8 characters long</li>
 * <li>Contains at least one uppercase letter</li>
 * <li>Contains at least one lowercase letter</li>
 * <li>Contains at least one digit</li>
 * <li>Contains at least one special symbol</li>
 * </ul>
 * </p>
 *
 * <p>
 * This implementation is stateless and thread-safe.
 * It is suitable for use in {@code dev}, {@code test}, and {@code prod}
 * profiles.
 * </p>
 */
@Component
public class DefaultPasswordPolicy implements PasswordPolicy {

    private static final int MIN_LENGTH = 8;
    private static final Pattern UPPERCASE = Pattern.compile("[A-Z]");
    private static final Pattern LOWERCASE = Pattern.compile("[a-z]");
    private static final Pattern DIGIT = Pattern.compile("[0-9]");
    private static final Pattern SPECIAL = Pattern.compile("[^a-zA-Z0-9]");

    @Override
    public void validate(String rawPassword) {
        if (rawPassword == null || rawPassword.isBlank()) {
            throw new IllegalArgumentException("Password cannot be empty");
        }

        if (rawPassword.length() < MIN_LENGTH) {
            throw new IllegalArgumentException("Password must be at least " + MIN_LENGTH + " characters long");
        }

        if (!UPPERCASE.matcher(rawPassword).find()) {
            throw new IllegalArgumentException("Password must contain at least one uppercase letter");
        }

        if (!LOWERCASE.matcher(rawPassword).find()) {
            throw new IllegalArgumentException("Password must contain at least one lowercase letter");
        }

        if (!DIGIT.matcher(rawPassword).find()) {
            throw new IllegalArgumentException("Password must contain at least one number");
        }

        if (!SPECIAL.matcher(rawPassword).find()) {
            throw new IllegalArgumentException("Password must contain at least one special symbol");
        }
    }
}
