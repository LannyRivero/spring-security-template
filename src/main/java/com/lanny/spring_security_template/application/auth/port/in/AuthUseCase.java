package com.lanny.spring_security_template.application.auth.port.in;

import com.lanny.spring_security_template.application.auth.command.*;
import com.lanny.spring_security_template.application.auth.result.*;

/**
 * High-level use case boundary for authentication and token management.
 * Defines core operations exposed to controllers or other application layers.
 */
public interface AuthUseCase {

    /**
     * Perform user authentication and issue JWT access + refresh tokens.
     */
    JwtResult login(LoginCommand command);

    /**
     * Validate and renew access token using refresh token.
     */
    JwtResult refresh(RefreshCommand command);

    /**
     * Return profile and authorities of the authenticated user.
     */
    MeResult me(String username);

    /**
     * Create a developer account in dev environments only.
     */
    void registerDev(RegisterCommand command);
}

