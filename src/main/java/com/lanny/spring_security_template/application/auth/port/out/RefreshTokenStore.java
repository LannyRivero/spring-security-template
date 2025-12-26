package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

/**
 * Outbound port for storing and managing Refresh Tokens with Family-Based Rotation.
 *
 * <p>
 * This interface abstracts the underlying persistence mechanism
 * (JPA, Redis, MongoDB, JDBC, KeyValueStore, InMemory, etc.) so the
 * application layer remains independent from infrastructure details.
 * </p>
 *
 * <h2>Refresh Token Rotation Strategy</h2>
 * <p>
 * Implements OWASP-recommended token rotation with reuse detection:
 * <ul>
 * <li><b>Family Tracking</b>: All tokens from the same auth session share a familyId</li>
 * <li><b>Token Chaining</b>: Each rotated token links to its predecessor via previousTokenJti</li>
 * <li><b>Reuse Detection</b>: Attempting to use a revoked token triggers family revocation</li>
 * <li><b>Automatic Mitigation</b>: Entire token family revoked on detected compromise</li>
 * </ul>
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Persist newly issued refresh tokens with family metadata</li>
 * <li>Verify whether a refresh token JTI exists and is not revoked</li>
 * <li>Revoke individual tokens (on rotation or logout)</li>
 * <li>Revoke entire token families (on reuse detection)</li>
 * <li>Delete all refresh tokens for a user (global logout)</li>
 * <li>Retrieve active tokens for audit and session management</li>
 * </ul>
 *
 * <h2>What this port does NOT do</h2>
 * <ul>
 * <li>No token validation or cryptographic verification</li>
 * <li>No JWT parsing — that belongs to {@code TokenProvider}</li>
 * <li>No business logic — only persistence of token metadata</li>
 * </ul>
 *
 * <h2>Recommended Implementations</h2>
 * <ul>
 * <li><b>Redis</b>: ideal for production — fast TTL eviction, perfect for sessions</li>
 * <li><b>JPA</b>: valid but heavier — for audit purposes and compliance</li>
 * <li><b>InMemory</b>: for test or demo profiles</li>
 * </ul>
 *
 * <h2>Integration with Refresh Token Rotation</h2>
 * <p>
 * When rotating refresh tokens, the application layer will:
 * <ol>
 * <li>Check that the old JTI exists and is not revoked</li>
 * <li>If revoked → Detect reuse → Revoke entire family</li>
 * <li>Issue a new refresh token with same familyId</li>
 * <li>Link new token to old token via previousTokenJti</li>
 * <li>Revoke the old JTI (normal rotation)</li>
 * <li>Store the new JTI</li>
 * </ol>
 * </p>
 */
public interface RefreshTokenStore {

    /**
     * Stores a new refresh token session for the user.
     *
     * @param username          the owner of the session
     * @param jti               the unique identifier of the refresh token (JWT ID)
     * @param familyId          the family identifier grouping rotated tokens
     * @param previousTokenJti  JTI of the token that was rotated (null for initial token)
     * @param issuedAt          timestamp when token was issued
     * @param expiresAt         timestamp when token expires
     */
    void save(String username, String jti, String familyId, String previousTokenJti, Instant issuedAt, Instant expiresAt);

    /**
     * Finds a refresh token by its JTI.
     * Used to check if token exists and retrieve its metadata (familyId, revoked status, etc.).
     *
     * @param jti unique token identifier
     * @return optional containing token data if found
     */
    Optional<RefreshTokenData> findByJti(String jti);

    /**
     * Revokes a specific refresh token by marking it as revoked.
     * Used during normal token rotation and logout.
     *
     * @param jti unique token identifier to revoke
     */
    void revoke(String refreshJti);

    /**
     * Revokes all tokens in a family.
     * Used when reuse is detected — prevents attacker from using any token in the chain.
     *
     * @param familyId the family identifier to revoke
     */
    void revokeFamily(String familyId);

    /**
     * Deletes all refresh tokens for a user.
     * Used for "logout-all-devices" flows and account deletion.
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

    /**
     * Atomically consumes a refresh token (marks as revoked and returns previous state).
     * Returns true if token was valid (not revoked), false if already revoked (reuse detected).
     *
     * @param jti unique token identifier
     * @return true if token was consumed successfully, false if already revoked
     * @deprecated Use {@link #findByJti(String)} + {@link #revoke(String)} for clearer semantics
     */
    @Deprecated(since = "1.2", forRemoval = true)
    void consume(String refreshJti);

    /**
     * Deletes all expired refresh tokens.
     * Should be called by a scheduled cleanup job.
     *
     * @param before delete tokens that expired before this instant
     * @return number of tokens deleted
     */
    int deleteExpiredTokens(Instant before);

    /**
     * Data transfer object for refresh token metadata.
     * Returned by {@link #findByJti(String)}.
     */
    record RefreshTokenData(
            String jti,
            String username,
            String familyId,
            String previousTokenJti,
            boolean revoked,
            Instant issuedAt,
            Instant expiresAt
    ) {
        /**
         * Checks if token is expired at the given instant.
         */
        public boolean isExpired(Instant now) {
            return now.isAfter(expiresAt);
        }
    }
}
