package com.lanny.spring_security_template.application.auth.port.in;

import com.lanny.spring_security_template.web.dto.AuthRequest;
import com.lanny.spring_security_template.web.dto.AuthResponse;
import com.lanny.spring_security_template.web.dto.RegisterRequest;

/**
 * Defines the input port for authentication-related use cases.
 * 
 * This interface is intentionally generic to serve as a reusable template
 * for future projects implementing Spring Security with JWT.
 */
public interface AuthUseCase {

    /**
     * Authenticates a user and issues a JWT token pair.
     *
     * @param request contains username/email and password.
     * @return AuthResponse containing access and refresh tokens.
     */
    AuthResponse login(AuthRequest request);

    /**
     * Registers a new user account.
     *
     * @param request contains username, password, and email.
     * @return AuthResponse with tokens for the newly registered user.
     */

    AuthResponse register(RegisterRequest request);

    /**
     * Refreshes an expired access token using a valid refresh token.
     *
     * @param refreshToken the valid refresh token.
     * @return AuthResponse with new access and refresh tokens.
     */
    AuthResponse refresh(String refreshToken);

    /**
     * Retrieves user details (authenticated principal).
     *
     * @param username the current authenticated username.
     * @return an AuthResponse or user profile information.
     */
    AuthResponse me(String username);
}
