package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Instant;
import java.util.List;

/**
 * Outbound port for storing and managing Refresh Tokens.
 *
 * <p>
 * This interface abstracts the underlying persistence mechanism
 * (JPA, Redis, MongoDB, JDBC, KeyValueStore, InMemory, etc.) so the
 * application layer remains independent from infrastructure details.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Persist newly issued refresh tokens (one per session/device).</li>
 * <li>Verify whether a refresh token JTI still exists (not revoked).</li>
 * <li>Delete a refresh token when it is used, rotated or invalidated.</li>
 * <li>Delete all refresh tokens for a user (full logout from all devices).</li>
 * <li>Retrieve all active refresh tokens for a user (auditing / session
 * mgmt).</li>
 * </ul>
 *
 * <h2>What this port does NOT do</h2>
 * <ul>
 * <li>No token validation or cryptographic verification.</li>
 * <li>No JWT parsing — that belongs to {@code TokenProvider}.</li>
 * <li>No business logic — only persistence of token metadata.</li>
 * </ul>
 *
 * <h2>Recommended Implementations</h2>
 * <ul>
 * <li><b>Redis</b>: ideal for production — fast TTL eviction, perfect for
 * sessions.</li>
 * <li><b>JPA</b>: valid but heavier — for audit purposes.</li>
 * <li><b>InMemory</b>: for test or demo profiles.</li>
 * </ul>
 *
 * <h2>Integration with Refresh Token Rotation</h2>
 * <p>
 * When rotating refresh tokens, the application layer will:
 * <ol>
 * <li>Check that the old JTI exists.</li>
 * <li>Issue a new refresh token.</li>
 * <li>Delete the old JTI.</li>
 * <li>Store the new JTI.</li>
 * </ol>
 * </p>
 */
public interface RefreshTokenStore {

    /**
     * Stores a new refresh token session for the user.
     *
     * @param username  the owner of the session
     * @param jti       the unique identifier of the refresh token (JWT ID)
     * @param issuedAt  timestamp when token was issued
     * @param expiresAt timestamp when token expires
     */
    void save(String username, String jti, Instant issuedAt, Instant expiresAt);  

    /**
     * Deletes all refresh tokens for a user.
     * Used for "logout-all-devices" flows.
     *
     * @param username user identifier
     */
    void deleteAllForUser(String username);

    /**
     * Retrieves all refresh token JTIs linked to the user.
     * Useful for auditing, session management, or admin consoles.
     *
     * @param username target user
     * @return list of active refresh token IDs
     */
    List<String> findAllForUser(String username);

    boolean consume(String jti);
}
