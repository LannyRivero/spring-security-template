package com.lanny.spring_security_template.infrastructure.jwt.key.file;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA Key Provider that loads keys directly from the filesystem.
 *
 * <p>
 * Intended for <b>production</b> deployments where keys are mounted
 * from secure external volumes (e.g. Kubernetes secrets, Docker volumes).
 * </p>
 *
 * <p>
 * Fail-fast behaviour is enforced: the application will not start if
 * keys are missing, unreadable, invalid, or inconsistent.
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

        Path privPath = Path.of(privateKeyPath);
        Path pubPath = Path.of(publicKeyPath);

        validateFile(privPath, "private");
        validateFile(pubPath, "public");

        try (InputStream privIs = Files.newInputStream(privPath);
                InputStream pubIs = Files.newInputStream(pubPath)) {

            this.privateKey = PemUtils.readPrivateKey(privIs);
            this.publicKey = PemUtils.readPublicKey(pubIs);

            validateKeyPair(publicKey, privateKey);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA key pair from filesystem.", e);
        }
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

    /**
     * Ensures that the public and private keys belong to the same RSA key pair.
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
