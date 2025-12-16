package com.lanny.spring_security_template.infrastructure.jwt.key.keystore;

import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;

import lombok.extern.slf4j.Slf4j;

/**
 * Secure RSA Key Provider for production environments.
 *
 * Loads RSA keys from a PKCS12 keystore and performs strict validation:
 * - key existence
 * - alias existence
 * - RSA type enforcement
 * - minimum key size (2048 bits)
 *
 * No sensitive file paths are logged to prevent leaking server structure.
 */
@Slf4j
@Component
@Profile("prod")
public class KeystoreRsaKeyProvider implements RsaKeyProvider {

    private final String kid;
    private final RSAPublicKey pub;
    private final RSAPrivateKey priv;

    public KeystoreRsaKeyProvider(
            @Value("${security.jwt.kid}") String kid,
            @Value("${security.jwt.keystore.path}") String keystorePath,
            @Value("${security.jwt.keystore.password}") String ksPassword,
            @Value("${security.jwt.keystore.key-alias}") String keyAlias,
            @Value("${security.jwt.keystore.key-password}") String keyPassword) {

        if (kid == null || kid.isBlank()) {
            throw new IllegalStateException("security.jwt.kid must be provided and non-blank.");
        }
        this.kid = kid;

        Path ksPath = Path.of(keystorePath);
        validateKeystoreFile(ksPath);

        try (FileInputStream fis = new FileInputStream(ksPath.toFile())) {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            ks.load(fis, ksPassword.toCharArray());

            Key key = ks.getKey(keyAlias, keyPassword.toCharArray());
            if (!(key instanceof RSAPrivateKey privKey)) {
                throw new IllegalStateException("Key alias does not reference an RSA private key: " + keyAlias);
            }

            X509Certificate cert = (X509Certificate) ks.getCertificate(keyAlias);
            if (cert == null) {
                throw new IllegalStateException("No certificate found for alias: " + keyAlias);
            }

            RSAPublicKey publicKey = (RSAPublicKey) cert.getPublicKey();

            validateKeySize(privKey, keyAlias);
            validateKeySize(publicKey, keyAlias);

            this.priv = privKey;
            this.pub = publicKey;

            // Secure log – no file paths exposed
            log.info("✓ Loaded RSA keypair for alias '{}'", keyAlias);

        } catch (Exception e) {
            throw new IllegalStateException("Could not load RSA keypair from keystore.", e);
        }
    }

    private static void validateKeystoreFile(Path ksPath) {
        if (!Files.exists(ksPath)) {
            throw new IllegalStateException("Keystore file does not exist: " + ksPath);
        }
        if (!Files.isRegularFile(ksPath)) {
            throw new IllegalStateException("Keystore path is not a file: " + ksPath);
        }
        if (!Files.isReadable(ksPath)) {
            throw new IllegalStateException("Keystore file is not readable: " + ksPath);
        }
    }

    private static void validateKeySize(RSAPrivateKey key, String alias) {
        if (key.getModulus().bitLength() < 2048) {
            throw new IllegalStateException(
                    "RSA private key for alias '" + alias + "' is too weak. Minimum size required: 2048 bits.");
        }
    }

    private static void validateKeySize(RSAPublicKey key, String alias) {
        if (key.getModulus().bitLength() < 2048) {
            throw new IllegalStateException(
                    "RSA public key for alias '" + alias + "' is too weak. Minimum size required: 2048 bits.");
        }
    }

    @Override
    public String keyId() {
        return kid;
    }

    @Override
    public RSAPublicKey publicKey() {
        return pub;
    }

    @Override
    public RSAPrivateKey privateKey() {
        return priv;
    }
}
