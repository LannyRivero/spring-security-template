package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Instant;

/**
 * Outbound port responsible for tracking revoked JWT tokens (by JTI).
 *
 * <p>
 * This abstraction allows the application layer to invalidate
 * previously issued tokens without relying on state within the JWT itself,
 * enabling security features such as:
 * </p>
 *
 * <ul>
 * <li>Manual logout</li>
 * <li>Refresh-token rotation</li>
 * <li>Force logout from all devices</li>
 * <li>Blocking compromised tokens</li>
 * <li>Brute-force mitigation</li>
 * </ul>
 *
 * <h2>What this port handles</h2>
 * <ul>
 * <li>Revocation of JWT tokens via their JTI.</li>
 * <li>Tracking expiration time in persistence to allow cleanup.</li>
 * <li>Checks whether a given token has been invalidated.</li>
 * </ul>
 *
 * <h2>What this port does NOT handle</h2>
 * <ul>
 * <li>No cryptographic validation (handled by TokenProvider).</li>
 * <li>No user-session management (handled by SessionManager).</li>
 * <li>No refresh-token storage (handled by RefreshTokenStore).</li>
 * <li>No automatic cleanup (handled by scheduled jobs).</li>
 * </ul>
 *
 * <h2>Recommended Implementations</h2>
 * <ul>
 * <li><b>Redis</b> (ideal for prod): fast TTL eviction + auto-cleanup.</li>
 * <li><b>JPA</b>: persistent auditing of revoked tokens.</li>
 * <li><b>InMemory</b>: testing/demo profiles.</li>
 * </ul>
 *
 * <h2>Why expiresAt matters?</h2>
 * <p>
 * Storing the expiration time enables safe TTL cleanup:
 * if token expired naturally, there's no need to keep its blacklist entry.
 * </p>
 */
public interface TokenBlacklistGateway {

    /**
     * Checks whether the given JWT token identifier (JTI)
     * has been explicitly revoked.
     *
     * <p>
     * This is called during authorization, after token signature
     * and expiration have already been successfully validated.
     * </p>
     *
     * @param jti unique token identifier extracted from the JWT
     * @return true if token is blacklisted, false otherwise
     */
    boolean isRevoked(String jti);

    /**
     * Revokes the JWT token by storing its JTI along with its expiration time.
     *
     * <p>
     * The expiration timestamp is used by infrastructure to schedule
     * automatic cleanup (Redis TTL, scheduled JPA cleanup, etc.).
     * </p>
     *
     * @param jti unique token identifier
     * @param exp JWT expiration timestamp (Instant.from exp claim)
     */
    void revoke(String jti, Instant exp);
}
