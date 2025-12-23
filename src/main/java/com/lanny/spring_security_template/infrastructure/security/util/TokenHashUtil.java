package com.lanny.spring_security_template.infrastructure.security.util;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Utility class for hashing sensitive token identifiers.
 *
 * <p>
 * This class is used to hash JWT identifiers (JTI) before persisting them,
 * ensuring that no sensitive token identifiers are stored in clear text.
 * </p>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Uses SHA-256 (one-way hash)</li>
 * <li>No salt required (JTI already high entropy)</li>
 * <li>Deterministic hashing for equality checks</li>
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
        // Utility class
    }

    /**
     * Hashes a JWT ID (JTI) using SHA-256.
     *
     * @param jti raw JWT identifier
     * @return hexadecimal SHA-256 hash
     * @throws IllegalStateException if SHA-256 is unavailable
     */
    public static String hashJti(String jti) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(
                    digest.digest(jti.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 unavailable", ex);
        }
    }
}
