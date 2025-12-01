package com.lanny.spring_security_template.application.auth.port.in;

import com.lanny.spring_security_template.application.auth.command.*;
import com.lanny.spring_security_template.application.auth.query.MeQuery;
import com.lanny.spring_security_template.application.auth.result.*;

/**
 * High-level boundary for authentication and identity-related use cases.
 *
 * <p>
 * Acts as the application service contract exposed to controllers or
 * other incoming adapters (REST, GraphQL, messaging, etc.).
 * </p>
 */
public interface AuthUseCase {

    /**
     * Authenticate a user using username/email + password
     * and issue access/refresh JWT tokens.
     */
    JwtResult login(LoginCommand command);

    /**
     * Validate and renew access token using a refresh token.
     */
    JwtResult refresh(RefreshCommand command);

    /**
     * Retrieve identity, roles and scopes of the authenticated user.
     *
     * <p>This is a read-only operation and therefore implemented
     * through a Query object instead of raw parameters.</p>
     */
    MeResult me(MeQuery query);

    /**
     * Create a developer-only account.
     *
     * <p>This method must be enabled only for the 'dev' profile and
     * never exposed in production environments.</p>
     */
    void registerDev(RegisterCommand command);

    /**
     * Change the password for the authenticated user.
     *
     * <p>
     * Delegates to a dedicated application service that validates:
     * <ul>
     *     <li>old password correctness</li>
     *     <li>password policy constraints</li>
     *     <li>revocation of active sessions if configured (session policy)</li>
     * </ul>
     * </p>
     */
    void changePassword(String username, String oldPassword, String newPassword);
}



