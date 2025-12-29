package com.lanny.spring_security_template.infrastructure.jwt.key.keystore;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Keystore-based RSA key provider (enterprise-grade).
 *
 * <p>
 * Activated when:
 * {@code security.jwt.rsa.source = keystore}
 *
 * <p>
 * Features:
 * <ul>
 * <li>Multi-kid verification</li>
 * <li>Single active signing key</li>
 * <li>Zero-downtime key rotation</li>
 * </ul>
 */
@Slf4j
@Component
@ConditionalOnProperty(prefix = "security.jwt.rsa", name = "source", havingValue = "keystore")
public class KeystoreRsaKeyProvider implements RsaKeyProvider {

    private static final int MIN_RSA_BITS = 2048;

    private final String activeKid;
    private final RSAPrivateKey privateKey;
    private final Map<String, RSAPublicKey> verificationKeys;

    public KeystoreRsaKeyProvider(SecurityJwtProperties props) {

        SecurityJwtProperties.RsaProperties rsa = requireRsa(props);
        SecurityJwtProperties.KeystoreProperties ks = rsa.keystore();

        this.activeKid = rsa.activeKid();

        KeyStore keyStore = loadKeystore(ks);

        this.privateKey = loadPrivateKey(
                keyStore,
                ks.kidAlias().get(activeKid),
                ks.keyPassword().toCharArray());

        this.verificationKeys = loadPublicKeys(
                keyStore,
                ks.kidAlias(),
                rsa.verificationKids());

        log.info(
                "✓ Loaded RSA keys from keystore [activeKid={}, verificationKids={}]",
                activeKid,
                verificationKeys.keySet());
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

    private static KeyStore loadKeystore(
            SecurityJwtProperties.KeystoreProperties ks) {

        Path path = normalizeAndValidatePath(ks.path());

        try (InputStream is = Files.newInputStream(path)) {
            KeyStore keyStore = KeyStore.getInstance(ks.type());
            keyStore.load(is, ks.password().toCharArray());
            return keyStore;
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load keystore from " + path, e);
        }
    }

    private RSAPrivateKey loadPrivateKey(
            KeyStore ks,
            String alias,
            char[] password) {

        requireText(alias, "keystore.kid-alias[activeKid]");

        try {
            Key key = ks.getKey(alias, password);
            if (!(key instanceof RSAPrivateKey priv)) {
                throw new IllegalStateException(
                        "Alias does not reference an RSA private key: " + alias);
            }
            validateKeySize(priv, alias);
            return priv;
        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA private key for alias: " + alias, e);
        }
    }

    private static Map<String, RSAPublicKey> loadPublicKeys(
            KeyStore ks,
            Map<String, String> kidAlias,
            List<String> verificationKids) {

        Map<String, RSAPublicKey> pubs = new HashMap<>();

        for (String kid : verificationKids) {
            String alias = requireText(
                    kidAlias.get(kid),
                    "keystore.kid-alias[" + kid + "]");

            try {
                X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
                if (cert == null) {
                    throw new IllegalStateException(
                            "No certificate found for alias: " + alias);
                }

                if (!(cert.getPublicKey() instanceof RSAPublicKey pub)) {
                    throw new IllegalStateException(
                            "Certificate public key is not RSA: " + alias);
                }

                validateKeySize(pub, alias);
                pubs.put(kid, pub);

            } catch (Exception e) {
                throw new IllegalStateException(
                        "Failed to load RSA public key for alias: " + alias, e);
            }
        }

        return Map.copyOf(pubs);
    }

    private static Path normalizeAndValidatePath(String rawPath) {
        requireText(rawPath, "keystore.path");
        Path path = Path.of(rawPath).normalize();

        if (!path.isAbsolute()) {
            throw new IllegalStateException(
                    "Keystore path must be absolute in production: " + path);
        }
        if (!Files.exists(path) || !Files.isReadable(path)) {
            throw new IllegalStateException(
                    "Keystore file does not exist or is not readable: " + path);
        }
        return path;
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

    private static SecurityJwtProperties.RsaProperties requireRsa(
            SecurityJwtProperties props) {

        if (props.rsa() == null) {
            throw new IllegalStateException(
                    "RSA configuration is required when algorithm=RSA");
        }
        return props.rsa();
    }

    private static String requireText(String value, String name) {
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must not be blank");
        }
        return value;
    }
}
