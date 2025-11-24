package com.lanny.spring_security_template.application.auth.command;

/**
 * Command object representing the input required for the Login use case.
 *
 * <p>
 * This command carries the raw credentials provided by the user:
 * a username (or email) and a raw password. No validation rules
 * should be enforced here — validation belongs in the application layer,
 * or via controllers using Bean Validation.
 * </p>
 *
 * <p>
 * The username field may contain either:
 * </p>
 * <ul>
 * <li>a system username (e.g., "johndoe")</li>
 * <li>an email address (e.g., "john@example.com")</li>
 * </ul>
 *
 * <p>
 * The use case (LoginService) decides how to interpret it.
 * </p>
 */
public record LoginCommand(
        String username,
        String password) {
}
