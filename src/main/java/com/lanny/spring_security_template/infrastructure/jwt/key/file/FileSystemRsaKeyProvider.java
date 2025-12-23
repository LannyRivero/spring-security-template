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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Filesystem-based RSA key provider with full multi-kid support.
 *
 * <p>
 * Supports zero-downtime key rotation by allowing:
 * <ul>
 * <li>One active signing key</li>
 * <li>Multiple verification keys (by kid)</li>
 * </ul>
 * </p>
 */
@Component
@Profile("prod")
public class FileSystemRsaKeyProvider implements RsaKeyProvider {

    private final String activeKid;
    private final RSAPrivateKey privateKey;
    private final Map<String, RSAPublicKey> verificationKeys;

    public FileSystemRsaKeyProvider(
            @Value("${security.jwt.active-kid}") String activeKid,
            @Value("${security.jwt.verification-kids}") List<String> verificationKids,
            @Value("${security.jwt.rsa.private-key-location}") String privateKeyPath,
            @Value("#{${security.jwt.rsa.public-keys}}") Map<String, String> publicKeyLocations) {

        this.activeKid = requireText(activeKid, "security.jwt.active-kid");

        if (verificationKids == null || verificationKids.isEmpty()) {
            throw new IllegalStateException("security.jwt.verification-kids must not be empty");
        }

        if (!verificationKids.contains(this.activeKid)) {
            throw new IllegalStateException(
                    "active-kid must be included in verification-kids");
        }

        // ============================
        // Load private key (ACTIVE)
        // ============================

        Path privPath = normalizeAndValidatePath(
                privateKeyPath, "private");

        validateFile(privPath, "private");
        validatePermissions(privPath, "private");

        try (InputStream is = Files.newInputStream(privPath)) {
            this.privateKey = PemUtils.readPrivateKey(is);
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA private key for active-kid=" + activeKid, e);
        }

        // ============================
        // Load verification public keys
        // ============================

        Map<String, RSAPublicKey> pubs = new HashMap<>();

        for (String kid : verificationKids) {
            String location = publicKeyLocations.get(kid);
            if (location == null || location.isBlank()) {
                throw new IllegalStateException(
                        "Missing public key location for kid: " + kid);
            }

            Path pubPath = normalizeAndValidatePath(location, "public");
            validateFile(pubPath, "public");
            validatePermissions(pubPath, "public");

            try (InputStream is = Files.newInputStream(pubPath)) {
                RSAPublicKey pub = PemUtils.readPublicKey(is);
                validateKeySize(pub, kid);
                pubs.put(kid, pub);
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Failed to load RSA public key for kid=" + kid, e);
            }
        }

        this.verificationKeys = Map.copyOf(pubs);
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
                    "RSA " + type + " key path must be absolute: " + path);
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
                    "RSA " + type + " key path is not a file: " + path);
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
            // Non-POSIX filesystem
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to validate permissions for RSA " + type + " key: " + path, e);
        }
    }

    private static void validateKeySize(RSAPublicKey key, String kid) {
        if (key.getModulus().bitLength() < 2048) {
            throw new IllegalStateException(
                    "RSA public key for kid '" + kid + "' is weaker than 2048 bits");
        }
    }

    private static String requireText(String value, String property) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(property + " must not be null or blank.");
        }
        return value;
    }
}
