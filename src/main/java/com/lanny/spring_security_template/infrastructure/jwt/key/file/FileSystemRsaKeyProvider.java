package com.lanny.spring_security_template.infrastructure.jwt.key.file;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA Key Provider that loads keys directly from the filesystem.
 *
 * <p>
 * This implementation is intended for <b>production</b> deployments,
 * where keys are stored securely in external volumes (e.g. /opt/keys/).
 * </p>
 *
 * <p>
 * Fail-fast behaviour is enforced: the application will not start if the
 * key files do not exist or cannot be parsed.
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
            throw new IllegalArgumentException("security.jwt.kid cannot be null or blank.");
        }
        this.kid = kid;

        Path privPath = Path.of(privateKeyPath);
        Path pubPath = Path.of(publicKeyPath);

        validateFile(privPath, "private");
        validateFile(pubPath, "public");

        try {
            this.privateKey = PemUtils.readPrivateKey(Files.newInputStream(privPath));
            this.publicKey = PemUtils.readPublicKey(Files.newInputStream(pubPath));
        } catch (Exception e) {
            throw new IllegalStateException("Failed to load RSA keys from filesystem.", e);
        }
    }

    private static void validateFile(Path path, String type) {
        if (!Files.exists(path)) {
            throw new IllegalStateException("RSA " + type + " key does not exist: " + path);
        }
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("RSA " + type + " key path is not a file: " + path);
        }
        if (!Files.isReadable(path)) {
            throw new IllegalStateException("RSA " + type + " key is not readable: " + path);
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
