package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * Utility class for loading RSA keys from PEM files.
 * Supports both classpath, filesystem, and InputStream sources.
 */
public final class PemUtils {

    private PemUtils() {
    }

    /*
     * ==========================================================
     * 🔐 Read by file path (current behaviour)
     * ==========================================================
     */
    public static RSAPrivateKey readPrivateKey(String location) {
        try {
            String pem = loadPem(location);
            return parsePrivateKey(pem);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read private key", e);
        }
    }

    public static RSAPublicKey readPublicKey(String location) {
        try {
            String pem = loadPem(location);
            return parsePublicKey(pem);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read public key", e);
        }
    }

    /*
     * ==========================================================
     * 🔄 New: read directly from InputStream (for KMS / remote)
     * ==========================================================
     */
    public static RSAPrivateKey readPrivateKey(InputStream is) {
        try {
            String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            return parsePrivateKey(pem);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read private key from stream", e);
        }
    }

    public static RSAPublicKey readPublicKey(InputStream is) {
        try {
            String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            return parsePublicKey(pem);
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read public key from stream", e);
        }
    }

    /*
     * ==========================================================
     * 🧩 Internal helpers
     * ==========================================================
     */
    private static RSAPrivateKey parsePrivateKey(String pem) throws Exception {
        String key = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        return (RSAPrivateKey) KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    private static RSAPublicKey parsePublicKey(String pem) throws Exception {
        String key = pem.replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(key);
        return (RSAPublicKey) KeyFactory.getInstance("RSA")
                .generatePublic(new X509EncodedKeySpec(decoded));
    }

    private static String loadPem(String location) throws IOException {
        // Try as classpath
        try (InputStream is = PemUtils.class.getResourceAsStream(location)) {
            if (is != null)
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }

        // Try with leading slash (classpath root)
        if (!location.startsWith("/")) {
            try (InputStream is = PemUtils.class.getResourceAsStream("/" + location)) {
                if (is != null)
                    return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        // Try as file path
        Path path = Path.of(location);
        if (Files.exists(path)) {
            return Files.readString(path, StandardCharsets.UTF_8);
        }

        throw new IllegalArgumentException("Key file not found: " + location);
    }
}
    