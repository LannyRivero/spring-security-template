package com.lanny.spring_security_template.infrastructure.jwt;

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

public class PemUtils {

    /**
     * Reads an RSA private key from either the classpath or an absolute file path.
     */
    public static RSAPrivateKey readPrivateKey(String location) {
        try {
            String pem = loadPem(location);
            String key = pem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replace("-----END PRIVATE KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] decoded = Base64.getDecoder().decode(key);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(decoded));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read private key", e);
        }
    }

    /**
     * Reads an RSA public key from either the classpath or an absolute file path.
     */
    public static RSAPublicKey readPublicKey(String location) {
        try {
            String pem = loadPem(location);
            String key = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");
            byte[] decoded = Base64.getDecoder().decode(key);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return (RSAPublicKey) kf.generatePublic(new X509EncodedKeySpec(decoded));
        } catch (Exception e) {
            throw new IllegalStateException("Cannot read public key", e);
        }
    }

    /**
     * Loads a PEM file from the classpath or filesystem.
     */
    private static String loadPem(String location) throws IOException {
        // Try as classpath resource first with original location
        try (InputStream is = PemUtils.class.getResourceAsStream(location)) {
            if (is != null) {
                return new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }
        }

        // Also try with leading '/' for classpath (only if not already present)
        if (!location.startsWith("/")) {
            try (InputStream is = PemUtils.class.getResourceAsStream("/" + location)) {
                if (is != null) {
                    return new String(is.readAllBytes(), StandardCharsets.UTF_8);
                }
            }
        }

        // Try as absolute or relative file path (use original location)
        Path path = Path.of(location);
        if (Files.exists(path)) {
            return Files.readString(path, StandardCharsets.UTF_8);
        }

        // If not found
        throw new IllegalArgumentException("Key file not found at: " + location);
    }
}