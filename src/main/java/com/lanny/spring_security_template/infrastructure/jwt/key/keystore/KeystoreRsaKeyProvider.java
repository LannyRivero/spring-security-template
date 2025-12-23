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
import java.util.*;

/**
 * {@code KeystoreRsaKeyProvider}
 *
 * <p>
 * Production-grade {@link RsaKeyProvider} supporting RSA key rotation
 * (multi-kid).
 * </p>
 *
 * <p>
 * Keys are loaded eagerly at startup and cached for the lifetime of the
 * application.
 * Any misconfiguration fails fast during boot.
 * </p>
 */
@Slf4j
@Component
@Profile("prod")
@ConditionalOnProperty(name = "security.jwt.key-provider", havingValue = "keystore")
public class KeystoreRsaKeyProvider implements RsaKeyProvider {

    private static final int MIN_RSA_KEY_SIZE = 2048;

    private final String activeKid;
    private final RSAPrivateKey privateKey;
    private final Map<String, RSAPublicKey> verificationKeys;

    public KeystoreRsaKeyProvider(
            @Value("${security.jwt.active-kid}") String activeKid,
            @Value("${security.jwt.verification-kids}") List<String> verificationKids,
            @Value("#{${security.jwt.keystore.kid-alias}}") Map<String, String> kidAliasMap,
            @Value("${security.jwt.keystore.path}") String keystorePath,
            @Value("${security.jwt.keystore.type:PKCS12}") String keystoreType,
            @Value("${security.jwt.keystore.password}") String keystorePassword,
            @Value("${security.jwt.keystore.key-password}") String keyPassword) {

        this.activeKid = requireText(activeKid, "security.jwt.active-kid");

        if (verificationKids == null || verificationKids.isEmpty()) {
            throw new IllegalStateException("security.jwt.verification-kids must not be empty.");
        }

        // Detect duplicate kids early
        Set<String> uniqueKids = new HashSet<>(verificationKids);
        if (uniqueKids.size() != verificationKids.size()) {
            throw new IllegalStateException(
                    "Duplicate kid detected in security.jwt.verification-kids");
        }

        if (!uniqueKids.contains(this.activeKid)) {
            throw new IllegalStateException(
                    "active-kid must be included in verification-kids.");
        }

        // Ensure alias coverage
        if (kidAliasMap == null || !kidAliasMap.keySet().containsAll(uniqueKids)) {
            throw new IllegalStateException(
                    "security.jwt.keystore.kid-alias must define aliases for all verification-kids");
        }

        Path ksPath = normalizeAndValidatePath(keystorePath);
        validateKeystoreFile(ksPath);

        try (InputStream is = Files.newInputStream(ksPath)) {

            KeyStore keyStore = KeyStore.getInstance(keystoreType);
            keyStore.load(is, keystorePassword.toCharArray());

            // --------------------------------------------------
            // Load ACTIVE signing key
            // --------------------------------------------------
            String activeAlias = requireText(
                    kidAliasMap.get(this.activeKid),
                    "security.jwt.keystore.kid-alias[" + this.activeKid + "]");

            this.privateKey = loadPrivateKey(
                    keyStore,
                    activeAlias,
                    keyPassword.toCharArray());

            // --------------------------------------------------
            // Load verification public keys (active + old)
            // --------------------------------------------------
            Map<String, RSAPublicKey> pubs = new HashMap<>();

            for (String kid : uniqueKids) {
                String alias = requireText(
                        kidAliasMap.get(kid),
                        "security.jwt.keystore.kid-alias[" + kid + "]");

                RSAPublicKey pub = loadPublicKey(keyStore, alias);
                validateKeySize(pub, alias);
                pubs.put(kid, pub);
            }

            this.verificationKeys = Map.copyOf(pubs);

            log.info(
                    "✓ Loaded RSA keys from keystore [type={}, activeKid={}, verificationKids={}]",
                    keystoreType,
                    this.activeKid,
                    this.verificationKeys.keySet());

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA keys from keystore. " +
                            "Check path, passwords, aliases and key formats.",
                    e);
        }
    }

    // --------------------------------------------------
    // RsaKeyProvider
    // --------------------------------------------------

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

    // --------------------------------------------------
    // Key loading helpers
    // --------------------------------------------------

    private RSAPrivateKey loadPrivateKey(
            KeyStore ks,
            String alias,
            char[] keyPassword) throws Exception {

        Key key = ks.getKey(alias, keyPassword);
        if (!(key instanceof RSAPrivateKey priv)) {
            throw new IllegalStateException(
                    "Alias does not reference an RSA private key: " + alias);
        }
        validateKeySize(priv, alias);
        return priv;
    }

    private RSAPublicKey loadPublicKey(
            KeyStore ks,
            String alias) throws Exception {

        X509Certificate cert = (X509Certificate) ks.getCertificate(alias);
        if (cert == null) {
            throw new IllegalStateException(
                    "No X509 certificate found for alias: " + alias);
        }
        if (!(cert.getPublicKey() instanceof RSAPublicKey pub)) {
            throw new IllegalStateException(
                    "Certificate public key is not RSA for alias: " + alias);
        }
        return pub;
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
}
