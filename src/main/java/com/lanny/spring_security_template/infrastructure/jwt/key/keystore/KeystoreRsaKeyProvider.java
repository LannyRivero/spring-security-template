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
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;

import lombok.extern.slf4j.Slf4j;

/**
 * RSA Key Provider backed by a PKCS12 keystore.
 *
 * <p>
 * This provider is intended for <b>production</b> environments and enforces
 * strict cryptographic validation and fail-fast behavior.
 * </p>
 */
@Slf4j
@Component
@Profile("prod")
@ConditionalOnProperty(name = "security.jwt.key-provider", havingValue = "keystore", matchIfMissing = false)
public class KeystoreRsaKeyProvider implements RsaKeyProvider {

    private final String kid;
    private final RSAPublicKey publicKey;
    private final RSAPrivateKey privateKey;

    public KeystoreRsaKeyProvider(
            @Value("${security.jwt.kid}") String kid,
            @Value("${security.jwt.keystore.path}") String keystorePath,
            @Value("${security.jwt.keystore.password}") String keystorePassword,
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
            ks.load(fis, keystorePassword.toCharArray());

            Key key = ks.getKey(keyAlias, keyPassword.toCharArray());
            if (!(key instanceof RSAPrivateKey priv)) {
                throw new IllegalStateException(
                        "Key alias does not reference an RSA private key: " + keyAlias);
            }

            X509Certificate cert = (X509Certificate) ks.getCertificate(keyAlias);
            if (cert == null) {
                throw new IllegalStateException(
                        "No certificate found for alias: " + keyAlias);
            }

            if (!"RSA".equalsIgnoreCase(cert.getPublicKey().getAlgorithm())) {
                throw new IllegalStateException(
                        "Certificate public key is not RSA for alias: " + keyAlias);
            }

            RSAPublicKey pub = (RSAPublicKey) cert.getPublicKey();

            validateKeySize(priv, keyAlias);
            validateKeySize(pub, keyAlias);
            validateKeyPair(pub, priv, keyAlias);

            this.privateKey = priv;
            this.publicKey = pub;

            log.info("✓ Loaded RSA keypair from keystore using alias '{}'", keyAlias);

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Could not load RSA keypair from keystore.", e);
        }
    }

    private static void validateKeystoreFile(Path path) {
        if (!Files.exists(path)) {
            throw new IllegalStateException("Keystore file does not exist.");
        }
        if (!Files.isRegularFile(path)) {
            throw new IllegalStateException("Keystore path is not a file.");
        }
        if (!Files.isReadable(path)) {
            throw new IllegalStateException("Keystore file is not readable.");
        }
    }

    private static void validateKeySize(RSAPrivateKey key, String alias) {
        if (key.getModulus().bitLength() < 2048) {
            throw new IllegalStateException(
                    "RSA private key for alias '" + alias + "' is weaker than 2048 bits.");
        }
    }

    private static void validateKeySize(RSAPublicKey key, String alias) {
        if (key.getModulus().bitLength() < 2048) {
            throw new IllegalStateException(
                    "RSA public key for alias '" + alias + "' is weaker than 2048 bits.");
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
