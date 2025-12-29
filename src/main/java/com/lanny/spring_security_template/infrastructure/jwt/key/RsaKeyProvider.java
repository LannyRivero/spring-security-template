package com.lanny.spring_security_template.infrastructure.jwt.key;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;

/**
 * Abstraction for RSA key access with support for zero-downtime key rotation.
 *
 * <p>
 * Implementations must provide:
 * <ul>
 * <li>One active signing key (identified by {@code activeKid})</li>
 * <li>One or more public keys for verification (multi-kid)</li>
 * </ul>
 *
 * <p>
 * This interface is infrastructure-facing and intentionally agnostic of:
 * <ul>
 * <li>Key source (filesystem, keystore, classpath, HSM, etc.)</li>
 * <li>Framework details (Spring, profiles, configuration)</li>
 * </ul>
 *
 * <p>
 * Typical implementations are selected via configuration
 * (e.g. {@code security.jwt.rsa.source}) and loaded eagerly at startup.
 */
public interface RsaKeyProvider {

    /**
     * Returns the {@code kid} of the active RSA key used to sign new JWTs.
     *
     * @return active signing key identifier
     */
    String activeKid();

    /**
     * Returns the RSA private key used for signing JWTs.
     *
     * <p>
     * This key MUST correspond to {@link #activeKid()}.
     *
     * @return active RSA private key
     */
    RSAPrivateKey privateKey();

    /**
     * Returns all RSA public keys accepted for JWT verification.
     *
     * <p>
     * The map key represents the {@code kid} value found in incoming JWT headers.
     *
     * @return immutable map of {@code kid → public key}
     */
    Map<String, RSAPublicKey> verificationKeys();

    /**
     * Resolves a public key by {@code kid}.
     *
     * @param kid key identifier from JWT header
     * @return matching public key, if present
     */
    default Optional<RSAPublicKey> findPublicKey(String kid) {
        return Optional.ofNullable(verificationKeys().get(kid));
    }
}
