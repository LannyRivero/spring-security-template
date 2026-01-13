package com.lanny.spring_security_template.infrastructure.security;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.service.PasswordHasher;

/**
 * Infrastructure-level implementation of the {@link PasswordHasher} domain
 * port.
 *
 * <p>
 * This component delegates password hashing and verification to Spring
 * Security's
 * 
 * {@link PasswordEncoder}, allowing the application to use strong, adaptive
 * hashing algorithms without coupling the domain to a specific implementation.
 * </p>
 *
 * <h2>Password hashing strategy</h2>
 * <p>
 * A
 * {@link org.springframework.security.crypto.password.DelegatingPasswordEncoder}
 * is expected to be provided by the infrastructure configuration.
 * </p>
 * <ul>
 * <li><b>Argon2</b> is used as the default algorithm for newly created password
 * hashes
 * in production environments.</li>
 * <li><b>BCrypt</b> is supported as a fallback for verifying legacy
 * hashes.</li>
 * </ul>
 *
 * <p>
 * The hashing algorithm is determined automatically based on the prefix
 * (e.g. {@code {argon2}}, {@code {bcrypt}}) stored with each password hash.
 * This enables safe algorithm upgrades without invalidating existing
 * credentials.
 * </p>
 *
 * <h2>Security considerations</h2>
 * <ul>
 * <li>Raw passwords are never persisted or logged.</li>
 * <li>Password verification is performed using constant-time comparisons
 * provided by the underlying encoder.</li>
 * <li>This component MUST NOT log raw or hashed passwords under any
 * circumstances.</li>
 * 
 * </ul>
 *
 * <p>
 * This implementation is designed for <b>production-grade, stateless APIs</b>
 * and complies with enterprise security best practices.
 * </p>
 */
@Component
public class PasswordHasherImpl implements PasswordHasher {

    private final PasswordEncoder encoder;

    public PasswordHasherImpl(PasswordEncoder encoder) {
        this.encoder = encoder;
    }

    /**
     * Hashes a raw password using a strong, adaptive hashing algorithm.
     *
     * @param rawPassword the plaintext password provided by the user
     * @return a securely hashed representation of the password, including
     *         the algorithm identifier prefix
     * @throws IllegalArgumentException if the provided password is null
     *                                  or the hash format is invalid
     * 
     */
    @Override
    public String hash(String rawPassword) {
        return encoder.encode(rawPassword);
    }

    /**
     * Verifies a raw password against a previously hashed password.
     *
     * @param rawPassword    the plaintext password to verify
     * @param hashedPassword the stored password hash
     * @return {@code true} if the password matches the hash; {@code false}
     *         otherwise
     * @throws IllegalArgumentException if the provided password is null
     *                                  or the hash format is invalid
     * 
     */
    @Override
    public boolean matches(String rawPassword, String hashedPassword) {
        return encoder.matches(rawPassword, hashedPassword);
    }
}
