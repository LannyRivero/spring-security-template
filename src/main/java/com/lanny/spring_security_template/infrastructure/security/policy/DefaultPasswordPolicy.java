package com.lanny.spring_security_template.infrastructure.security.policy;

import java.util.regex.Pattern;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.policy.PasswordPolicy;

/**
 * ============================================================
 * DefaultPasswordPolicy
 * ============================================================
 *
 * <p>
 * Default, deterministic implementation of {@link PasswordPolicy}
 * enforcing a baseline password complexity suitable for
 * modern enterprise applications.
 * </p>
 *
 * <h2>Validation rules</h2>
 * <ul>
 * <li>Minimum length</li>
 * <li>At least one uppercase letter</li>
 * <li>At least one lowercase letter</li>
 * <li>At least one digit</li>
 * <li>At least one non-alphanumeric character</li>
 * </ul>
 *
 * <h2>Contract</h2>
 * <ul>
 * <li>Validation is deterministic</li>
 * <li>Validation is fail-fast (first violation stops evaluation)</li>
 * <li>Throws {@link IllegalArgumentException} on violation</li>
 * <li>Does not return validation details as structured data</li>
 * </ul>
 *
 * <h2>Security characteristics</h2>
 * <ul>
 * <li>No password values are logged</li>
 * <li>No hashing or encoding is performed</li>
 * <li>No state is stored</li>
 * </ul>
 *
 * <h2>Intended usage</h2>
 * <p>
 * This policy is suitable for:
 * </p>
 * <ul>
 * <li>User registration</li>
 * <li>Password change flows</li>
 * <li>Credential resets</li>
 * </ul>
 *
 * <h2>Limitations</h2>
 * <ul>
 * <li>Rules are static and not externally configurable</li>
 * <li>No support for contextual or adaptive policies</li>
 * <li>No password history or breach detection</li>
 * </ul>
 *
 * <p>
 * More advanced password policies (entropy-based, breached-password
 * checks, tenant-specific rules) should be implemented as separate
 * {@link PasswordPolicy} implementations.
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
            throw new IllegalArgumentException("Password must not be empty");
        }

        if (rawPassword.length() < MIN_LENGTH) {
            throw new IllegalArgumentException(
                    "Password must be at least " + MIN_LENGTH + " characters long");
        }

        if (!UPPERCASE.matcher(rawPassword).find()) {
            throw new IllegalArgumentException(
                    "Password must contain at least one uppercase letter");
        }

        if (!LOWERCASE.matcher(rawPassword).find()) {
            throw new IllegalArgumentException(
                    "Password must contain at least one lowercase letter");
        }

        if (!DIGIT.matcher(rawPassword).find()) {
            throw new IllegalArgumentException(
                    "Password must contain at least one digit");
        }

        if (!SPECIAL.matcher(rawPassword).find()) {
            throw new IllegalArgumentException(
                    "Password must contain at least one special character");
        }
    }
}
