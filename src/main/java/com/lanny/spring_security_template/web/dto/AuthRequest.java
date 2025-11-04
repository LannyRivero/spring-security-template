package com.lanny.spring_security_template.web.dto;

/**
 * Data Transfer Object for authentication requests.
 *
 * @param username the user's username or email.
 * @param password the user's password.
 */
public record AuthRequest(
        String username,
        String password) {
}
