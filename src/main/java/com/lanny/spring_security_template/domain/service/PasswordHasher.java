package com.lanny.spring_security_template.domain.service;

/**
 * Domain abstraction for password hashing and verification.
 *
 * Keeps domain pure by avoiding dependency on Spring Security.
 */
public interface PasswordHasher {

    /**
     * Hash a raw password using a secure one-way algorithm.
     */
    String hash(String rawPassword);

    /**
     * Check if a raw password matches an existing hash.
     */
    boolean matches(String rawPassword, String hashedPassword);
}
