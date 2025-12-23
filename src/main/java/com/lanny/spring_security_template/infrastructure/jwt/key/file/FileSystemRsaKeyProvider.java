package com.lanny.spring_security_template.infrastructure.jwt.key.file;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Set;

/**
 * {@code FileSystemRsaKeyProvider}
 *
 * <p>
 * Production-grade RSA key provider loading keys from filesystem.
 * Single-key implementation adapted to multi-kid contract.
 * </p>
 */
@Component
@Profile("prod")
public class FileSystemRsaKeyProvider implements RsaKeyProvider {

    private final String activeKid;
    private final RSAPrivateKey privateKey;
    private final Map<String, RSAPublicKey> verificationKeys;

    public FileSystemRsaKeyProvider(
            @Value("${security.jwt.kid}") String kid,
            @Value("${security.jwt.rsa.private-key-location}") String privateKeyPath,
            @Value("${security.jwt.rsa.public-key-location}") String publicKeyPath) {

        this.activeKid = requireText(kid, "security.jwt.kid");

        Path privPath = normalizeAndValidatePath(privateKeyPath, "private");
        Path pubPath = normalizeAndValidatePath(publicKeyPath, "public");

        validateFile(privPath, "private");
        validateFile(pubPath, "public");

        validatePermissions(privPath, "private");
        validatePermissions(pubPath, "public");

        try (InputStream privIs = Files.newInputStream(privPath);
                InputStream pubIs = Files.newInputStream(pubPath)) {

            RSAPrivateKey privateKey = PemUtils.readPrivateKey(privIs);
            RSAPublicKey publicKey = PemUtils.readPublicKey(pubIs);

            validateKeyPair(publicKey, privateKey);

            this.privateKey = privateKey;

            // 🔑 Single kid, but multi-kid ready
            this.verificationKeys = Map.of(this.activeKid, publicKey);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA key pair from filesystem (prod profile).", e);
        }
    }

    // ======================================================
    // RsaKeyProvider
    // ======================================================

    @Override
    public String activeKid() {
        return activeKid;
    }

    @Override
    public RSAPrivateKey privateKey() {
        return privateKey;
    }

    @Override
    public Map<String, RSAPublicKey> verificationKeys() {
        return verificationKeys;
    }

    // ======================================================
    // Internals
    // ======================================================

    private static Path normalizeAndValidatePath(String rawPath, String type) {
        if (rawPath == null || rawPath.isBlank()) {
            throw new IllegalStateException(
                    "RSA " + type + " key path must not be null or blank.");
        }

        Path path = Path.of(rawPath).normalize();

        if (!path.isAbsolute()) {
            throw new IllegalStateException(
                    "RSA " + type + " key path must be absolute in production: " + path);
        }
        return path;
    }

    private static void validateFile(Path path, String type) {
        if (!Files.exists(path)) {
            throw new IllegalStateException(
                    "RSA " + type + " key does not exist: " + path);
        }
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException(
                    "RSA " + type + " key path is not a regular file: " + path);
        }
        if (!Files.isReadable(path)) {
            throw new IllegalStateException(
                    "RSA " + type + " key is not readable: " + path);
        }
    }

    private static void validatePermissions(Path path, String type) {
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            if (perms.contains(PosixFilePermission.OTHERS_READ)) {
                throw new IllegalStateException(
                        "RSA " + type + " key must not be world-readable: " + path);
            }
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX FS (Windows)
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to validate permissions for RSA " + type + " key: " + path, e);
        }
    }

    private static void validateKeyPair(
            RSAPublicKey publicKey,
            RSAPrivateKey privateKey) {

        if (!publicKey.getModulus().equals(privateKey.getModulus())) {
            throw new IllegalStateException(
                    "Public and private RSA keys do not match (modulus mismatch).");
        }
    }

    private static String requireText(String value, String property) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(property + " must not be null or blank.");
        }
        return value;
    }
}
