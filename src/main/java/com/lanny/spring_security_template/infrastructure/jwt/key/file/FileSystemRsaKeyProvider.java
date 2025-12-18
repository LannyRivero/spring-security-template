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
import java.util.Set;

/**
 * {@code FileSystemRsaKeyProvider}
 *
 * <p>
 * Production-grade {@link RsaKeyProvider} that loads RSA public/private keys
 * directly from the filesystem.
 * </p>
 *
 * <h3>Intended usage</h3>
 * <ul>
 * <li>Production environments</li>
 * <li>Docker / Docker Compose (mounted volumes)</li>
 * <li>Kubernetes Secrets mounted as files</li>
 * <li>VMs with protected filesystem paths</li>
 * </ul>
 *
 * <p>
 * This provider enforces <b>fail-fast</b> behaviour: the application
 * will not start if keys are missing, unreadable, invalid, or inconsistent.
 * </p>
 *
 * <p>
 * <b>Security guarantees:</b>
 * <ul>
 * <li>Only absolute filesystem paths are accepted</li>
 * <li>Paths are normalized to prevent traversal attacks</li>
 * <li>Basic file permissions are validated</li>
 * <li>RSA public/private key pair consistency is enforced</li>
 * </ul>
 * </p>
 *
 * <p>
 * <b>NOTE:</b> This provider is intentionally limited to filesystem-based
 * secrets. For higher security requirements, prefer a dedicated
 * KMS/Vault-based implementation.
 * </p>
 */
@Component
@Profile("prod")
public class FileSystemRsaKeyProvider implements RsaKeyProvider {

    private final String kid;
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public FileSystemRsaKeyProvider(
            @Value("${security.jwt.kid}") String kid,
            @Value("${security.jwt.rsa.private-key-location}") String privateKeyPath,
            @Value("${security.jwt.rsa.public-key-location}") String publicKeyPath) {

        if (kid == null || kid.isBlank()) {
            throw new IllegalArgumentException(
                    "security.jwt.kid cannot be null or blank.");
        }
        this.kid = kid;

        Path privPath = normalizeAndValidatePath(privateKeyPath, "private");
        Path pubPath = normalizeAndValidatePath(publicKeyPath, "public");

        validateFile(privPath, "private");
        validateFile(pubPath, "public");

        validatePermissions(privPath, "private");
        validatePermissions(pubPath, "public");

        try (InputStream privIs = Files.newInputStream(privPath);
                InputStream pubIs = Files.newInputStream(pubPath)) {

            this.privateKey = PemUtils.readPrivateKey(privIs);
            this.publicKey = PemUtils.readPublicKey(pubIs);

            validateKeyPair(publicKey, privateKey);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA key pair from filesystem (prod profile). " +
                            "Check file paths, permissions and key format.",
                    e);
        }
    }

    /**
     * Normalizes and validates that the provided path is absolute.
     */
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

    /**
     * Validates existence, type and readability of the key file.
     */
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

    /**
     * Performs basic POSIX permission hardening.
     *
     * <p>
     * Rejects keys that are world-readable when running on
     * POSIX-compliant filesystems.
     * </p>
     */
    private static void validatePermissions(Path path, String type) {
        try {
            Set<PosixFilePermission> perms = Files.getPosixFilePermissions(path);
            if (perms.contains(PosixFilePermission.OTHERS_READ)) {
                throw new IllegalStateException(
                        "RSA " + type + " key must not be world-readable: " + path);
            }
        } catch (UnsupportedOperationException ignored) {
            // Non-POSIX filesystem (e.g. Windows) → skip permission validation
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to validate permissions for RSA " + type + " key: " + path, e);
        }
    }

    /**
     * Ensures that the public and private RSA keys belong to the same key pair.
     */
    private static void validateKeyPair(
            RSAPublicKey publicKey,
            RSAPrivateKey privateKey) {

        if (!publicKey.getModulus().equals(privateKey.getModulus())) {
            throw new IllegalStateException(
                    "Public and private RSA keys do not match (modulus mismatch).");
        }
    }

    @Override
    public String keyId() {
        return kid;
    }

    @Override
    public RSAPublicKey publicKey() {
        return publicKey;
    }

    @Override
    public RSAPrivateKey privateKey() {
        return privateKey;
    }
}
