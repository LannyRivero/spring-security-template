package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;

/**
 * Outbound port abstracting all JWT operations.
 *
 * <p>
 * This interface isolates the application layer from the concrete JWT
 * implementation (Nimbus, JJWT, Auth0 Java JWT, custom signer, etc.).
 * </p>
 *
 * <p>
 * Responsibilities:
 * </p>
 * <ul>
 * <li>Issue access and refresh tokens</li>
 * <li>Validate integrity & expiration</li>
 * <li>Extract claims (subject, jti, roles, scopes, timestamps)</li>
 * <li>Parse JWTs into a normalised DTO</li>
 * </ul>
 *
 * <p>
 * <b>Important:</b> Implementations MUST be fully stateless.
 * No caching of tokens, keys or validation state inside the provider itself.
 * Validation must depend solely on:
 * <ul>
 * <li>Crypto material (keys)</li>
 * <li>Token structure</li>
 * <li>Token timestamps (iat, nbf, exp)</li>
 * </ul>
 * </p>
 */
public interface TokenProvider {

    /**
     * Generates a signed Access Token with:
     * <ul>
     * <li>subject (user ID or username)</li>
     * <li>roles (RBAC)</li>
     * <li>scopes (fine-grained permissions)</li>
     * <li>custom TTL (time-to-live)</li>
     * </ul>
     *
     * @param subject unique identifier of the authenticated user
     * @param roles   list of granted roles
     * @param scopes  list of granted scopes
     * @param ttl     validity duration
     * @return signed JWT access token
     */
    String generateAccessToken(String subject,
            List<String> roles,
            List<String> scopes,
            Duration ttl);

    /**
     * Generates a signed Refresh Token with longer expiration.
     * Includes a jti (unique ID) for revocation tracking.
     *
     * @param subject user ID or username
     * @param ttl     refresh lifespan
     * @return signed JWT refresh token
     */
    String generateRefreshToken(String subject, Duration ttl);

    /**
     * Performs only cryptographic and time-based validation.
     *
     * <p>
     * No database checks, no revocation checks—
     * that logic belongs to SessionManager / RefreshTokenStore.
     * </p>
     *
     * @param token raw JWT
     * @return true if signature, structure and expiration are valid
     */
    boolean validateToken(String token);

    /**
     * Extracts the "sub" claim without fully parsing the JWT.
     * Useful in Security Filters.
     *
     * @param token raw JWT
     * @return subject (user ID, username, etc.)
     */
    String extractSubject(String token);

    /**
     * Parses all standard claims without validating expiration.
     * (Signature should still be validated internally.)
     *
     * @param token raw JWT
     * @return normalized claims OR empty if invalid
     */
    Optional<TokenClaims> parseClaims(String token);

    /**
     * Validates signature & expiration AND returns a DTO containing
     * all normalized claims.
     *
     * <p>
     * This is the high-level API used typically by controllers
     * or authentication filters.
     * </p>
     *
     * @param token raw JWT
     * @return normalized claims DTO if valid
     */
    Optional<JwtClaimsDTO> validateAndGetClaims(String token);

    /**
     * Extracts the JTI (unique identifier) used for:
     * <ul>
     * <li>Refresh token revocation</li>
     * <li>Session tracking</li>
     * </ul>
     */
    String extractJti(String token);

    /**
     * Normalised view of JWT claims returned by {@link #parseClaims(String)}.
     *
     * <p>
     * ⚠ NOT returned to the client — internal usage only.
     * </p>
     */
    record TokenClaims(
            String sub,
            List<String> roles,
            List<String> scopes,
            long iat,
            long exp,
            String jti,
            String iss,
            List<String> aud) {
    }
}
