package com.lanny.spring_security_template.application.auth.command;

import java.util.List;

/**
 * Command for the user registration use case.
 *
 * <p>
 * This class represents the payload required to create a new account in
 * development environments (registration is typically disabled in production).
 * </p>
 *
 * <p>
 * It carries:
 * </p>
 * <ul>
 * <li>username — raw, not normalized</li>
 * <li>email — raw, not normalized</li>
 * <li>rawPassword — unencrypted, to be hashed by PasswordHasher</li>
 * <li>roles — list of role names to assign to the user</li>
 * <li>scopes — optional additional fine-grained permissions</li>
 * </ul>
 *
 * <p>
 * Business rules such as:
 * </p>
 * <ul>
 * <li>username and email uniqueness</li>
 * <li>password strength</li>
 * <li>role existence and validation</li>
 * </ul>
 * <p>
 * must be enforced in the application/domain layers.
 * </p>
 */
public record RegisterCommand(
                String username,
                String email,
                String rawPassword,
                List<String> roles,
                List<String> scopes) {
}
