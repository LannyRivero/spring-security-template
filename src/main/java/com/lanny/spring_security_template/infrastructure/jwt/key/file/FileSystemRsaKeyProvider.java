package com.lanny.spring_security_template.infrastructure.jwt.key.file;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
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
 * Filesystem-based RSA key provider.
 *
 * <p>
 * Activated when:
 * {@code security.jwt.rsa.source = filesystem}
 *
 * <p>
 * Supports:
 * <ul>
 * <li>Single active signing key</li>
 * <li>Multiple verification keys (multi-kid)</li>
 * <li>Zero-downtime key rotation</li>
 * </ul>
 */
@Component
@ConditionalOnProperty(prefix = "security.jwt.rsa", name = "source", havingValue = "filesystem")
public class FileSystemRsaKeyProvider implements RsaKeyProvider {

    private static final int MIN_RSA_BITS = 2048;

    private final String activeKid;
    private final RSAPrivateKey privateKey;
    private final Map<String, RSAPublicKey> verificationKeys;

    public FileSystemRsaKeyProvider(SecurityJwtProperties props) {

        SecurityJwtProperties.RsaProperties rsa = requireRsa(props);

        this.activeKid = rsa.activeKid();

        List<String> verificationKids = rsa.verificationKids();
        if (!verificationKids.contains(activeKid)) {
            throw new IllegalStateException(
                    "activeKid must be included in verificationKids");
        }

        // ---------- Private key ----------
        Path privatePath = normalizeAndValidatePath(
                rsa.privateKeyLocation(), "private");

        this.privateKey = loadPrivateKey(privatePath);

        // ---------- Public keys ----------
        Map<String, RSAPublicKey> pubs = new HashMap<>();

        for (String kid : verificationKids) {
            String location = requireText(
                    rsa.publicKeys().get(kid),
                    "security.jwt.rsa.publicKeys[" + kid + "]");

            Path pubPath = normalizeAndValidatePath(location, "public");
            RSAPublicKey pub = loadPublicKey(pubPath, kid);
            pubs.put(kid, pub);
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

    private static SecurityJwtProperties.RsaProperties requireRsa(SecurityJwtProperties props) {
        if (props.rsa() == null) {
            throw new IllegalStateException(
                    "RSA configuration is required when algorithm=RSA");
        }
        return props.rsa();
    }

    private static RSAPrivateKey loadPrivateKey(Path path) {
        validateFile(path, "private");
        validatePermissions(path, "private");

        try (InputStream is = Files.newInputStream(path)) {
            RSAPrivateKey key = PemUtils.readPrivateKey(is);
            validateKeySize(key, path.toString());
            return key;
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA private key: " + path, e);
        }
    }

    private static RSAPublicKey loadPublicKey(Path path, String kid) {
        validateFile(path, "public");
        validatePermissions(path, "public");

        try (InputStream is = Files.newInputStream(path)) {
            RSAPublicKey key = PemUtils.readPublicKey(is);
            validateKeySize(key, kid);
            return key;
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA public key for kid=" + kid, e);
        }
    }

    private static Path normalizeAndValidatePath(String rawPath, String type) {
        requireText(rawPath, "RSA " + type + " key path");
        Path path = Path.of(rawPath).normalize();
        if (!path.isAbsolute()) {
            throw new IllegalStateException(
                    "RSA " + type + " key path must be absolute: " + path);
        }
        return path;
    }

    private static void validateFile(Path path, String type) {
        if (!Files.exists(path) || !Files.isReadable(path) || !Files.isRegularFile(path)) {
            throw new IllegalStateException(
                    "RSA " + type + " key is invalid: " + path);
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

    private static void validateKeySize(RSAPrivateKey key, String ref) {
        if (key.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new IllegalStateException(
                    "RSA private key too weak (<2048 bits): " + ref);
        }
    }

    private static void validateKeySize(RSAPublicKey key, String ref) {
        if (key.getModulus().bitLength() < MIN_RSA_BITS) {
            throw new IllegalStateException(
                    "RSA public key too weak (<2048 bits): " + ref);
        }
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must not be blank");
        }
        return value;
    }
}
