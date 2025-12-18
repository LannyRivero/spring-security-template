package com.lanny.spring_security_template.infrastructure.jwt.key.keystore;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * {@code KeystoreRsaKeyProvider}
 *
 * <p>
 * Production-grade {@link RsaKeyProvider} that loads an RSA key pair
 * from a Java {@link KeyStore} (PKCS12 or JKS).
 * </p>
 *
 * <h3>Security guarantees</h3>
 * <ul>
 * <li>Alias is mandatory and explicit</li>
 * <li>Keystore password and key password are separated</li>
 * <li>Supports PKCS12 and JKS formats</li>
 * <li>Minimum RSA key size of 2048 bits enforced</li>
 * <li>Public certificate must match private key</li>
 * <li>Fail-fast on any misconfiguration</li>
 * </ul>
 *
 * <h3>Typical usage</h3>
 * <ul>
 * <li>Enterprise production environments</li>
 * <li>Kubernetes Secrets / Vault exports</li>
 * <li>Key rotation via alias + kid</li>
 * </ul>
 *
 * <p>
 * This provider is activated only when:
 * <ul>
 * <li>{@code profile=prod}</li>
 * <li>{@code security.jwt.key-provider=keystore}</li>
 * </ul>
 * </p>
 */
@Slf4j
@Component
@Profile("prod")
@ConditionalOnProperty(name = "security.jwt.key-provider", havingValue = "keystore")
public class KeystoreRsaKeyProvider implements RsaKeyProvider {

    private static final int MIN_RSA_KEY_SIZE = 2048;

    private final String kid;
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public KeystoreRsaKeyProvider(
            @Value("${security.jwt.kid}") String kid,
            @Value("${security.jwt.keystore.path}") String keystorePath,
            @Value("${security.jwt.keystore.type:PKCS12}") String keystoreType,
            @Value("${security.jwt.keystore.password}") String keystorePassword,
            @Value("${security.jwt.keystore.key-alias}") String keyAlias,
            @Value("${security.jwt.keystore.key-password}") String keyPassword) {

        this.kid = requireText(kid, "security.jwt.kid");
        requireText(keyAlias, "security.jwt.keystore.key-alias");

        Path ksPath = normalizeAndValidatePath(keystorePath);
        validateKeystoreFile(ksPath);

        try (InputStream is = Files.newInputStream(ksPath)) {

            KeyStore keyStore = KeyStore.getInstance(keystoreType);
            keyStore.load(is, keystorePassword.toCharArray());

            Key key = keyStore.getKey(keyAlias, keyPassword.toCharArray());
            if (!(key instanceof RSAPrivateKey priv)) {
                throw new IllegalStateException(
                        "Alias does not reference an RSA private key: " + keyAlias);
            }

            X509Certificate cert = (X509Certificate) keyStore.getCertificate(keyAlias);
            if (cert == null) {
                throw new IllegalStateException(
                        "No X509 certificate found for alias: " + keyAlias);
            }

            if (!(cert.getPublicKey() instanceof RSAPublicKey pub)) {
                throw new IllegalStateException(
                        "Certificate public key is not RSA for alias: " + keyAlias);
            }

            validateKeySize(priv, keyAlias);
            validateKeySize(pub, keyAlias);
            validateKeyPair(pub, priv, keyAlias);

            this.privateKey = priv;
            this.publicKey = pub;

            log.info("✓ Loaded RSA keypair from keystore [type={}, alias={}, kid={}]",
                    keystoreType, keyAlias, kid);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA keypair from keystore. " +
                            "Check keystore path, passwords, alias and key format.",
                    e);
        }
    }

    // --------------------------------------------------
    // Validation helpers
    // --------------------------------------------------

    private static String requireText(String value, String property) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(property + " must not be null or blank.");
        }
        return value;
    }

    private static Path normalizeAndValidatePath(String rawPath) {
        Path path = Path.of(requireText(rawPath, "security.jwt.keystore.path")).normalize();
        if (!path.isAbsolute()) {
            throw new IllegalStateException(
                    "Keystore path must be absolute in production: " + path);
        }
        return path;
    }

    private static void validateKeystoreFile(Path path) {
        if (!Files.exists(path)) {
            throw new IllegalStateException("Keystore file does not exist: " + path);
        }
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("Keystore path is not a file: " + path);
        }
        if (!Files.isReadable(path)) {
            throw new IllegalStateException("Keystore file is not readable: " + path);
        }
    }

    private static void validateKeySize(RSAPrivateKey key, String alias) {
        if (key.getModulus().bitLength() < MIN_RSA_KEY_SIZE) {
            throw new IllegalStateException(
                    "RSA private key for alias '" + alias + "' is weaker than "
                            + MIN_RSA_KEY_SIZE + " bits.");
        }
    }

    private static void validateKeySize(RSAPublicKey key, String alias) {
        if (key.getModulus().bitLength() < MIN_RSA_KEY_SIZE) {
            throw new IllegalStateException(
                    "RSA public key for alias '" + alias + "' is weaker than "
                            + MIN_RSA_KEY_SIZE + " bits.");
        }
    }

    private static void validateKeyPair(
            RSAPublicKey pub,
            RSAPrivateKey priv,
            String alias) {

        if (!pub.getModulus().equals(priv.getModulus())) {
            throw new IllegalStateException(
                    "Public certificate does not match private key for alias '" + alias + "'.");
        }
    }

    // --------------------------------------------------
    // RsaKeyProvider
    // --------------------------------------------------

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
