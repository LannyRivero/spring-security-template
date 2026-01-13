package com.lanny.spring_security_template.infrastructure.security.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * ============================================================
 * TokenHashUtil
 * ============================================================
 *
 * <p>
 * Utility class for hashing sensitive token identifiers before persistence.
 * </p>
 *
 * <p>
 * This utility is primarily used to hash JWT identifiers (JTI) so that
 * no sensitive token identifiers are ever stored in clear text.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Uses SHA-256 (one-way cryptographic hash)</li>
 * <li>No reversible transformation (hashing, not encryption)</li>
 * <li>Deterministic output for equality and lookup operations</li>
 * </ul>
 *
 * <h2>Design rationale</h2>
 * <ul>
 * <li>JTI values are high-entropy and randomly generated</li>
 * <li>No salt is required to prevent precomputation attacks</li>
 * <li>Hashing enables secure comparison without storing raw identifiers</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>Pure utility class (no Spring dependencies)</li>
 * <li>Stateless and thread-safe</li>
 * <li>Infrastructure-level concern</li>
 * </ul>
 */
public final class TokenHashUtil {

    private TokenHashUtil() {
        // Utility class — prevent instantiation
    }

    /**
     * Hashes a JWT ID (JTI) using SHA-256 and returns a hexadecimal representation.
     *
     * <p>
     * The resulting hash can be safely persisted and compared without exposing
     * the original token identifier.
     * </p>
     *
     * @param jti the raw JWT identifier (must not be null or blank)
     * @return hexadecimal SHA-256 hash of the JTI
     *
     * @throws IllegalArgumentException if the provided JTI is null or blank
     * @throws IllegalStateException    if the SHA-256 algorithm is unavailable
     */
    public static String hashJti(String jti) {

        if (jti == null || jti.isBlank()) {
            throw new IllegalArgumentException("JTI must not be null or blank");
        }

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(jti.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);

        } catch (NoSuchAlgorithmException ex) {
            // This should never happen in a compliant JVM
            throw new IllegalStateException("SHA-256 algorithm is unavailable", ex);
        }
    }
}
