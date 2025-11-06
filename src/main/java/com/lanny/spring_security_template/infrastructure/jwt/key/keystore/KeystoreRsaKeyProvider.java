package com.lanny.spring_security_template.infrastructure.jwt.key.keystore;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * 🔐 KeystoreRsaKeyProvider
 *
 * Loads RSA keypair from a secure PKCS12 / JKS keystore in production.
 * Supports file path or environment variable-based configuration.
 *
 * Example configuration:
 * security.jwt.kid=prod-rsa-1
 * security.jwt.keystore.path=/opt/keys/security-template.p12
 * security.jwt.keystore.password=${KEYSTORE_PASSWORD}
 * security.jwt.keystore.key-alias=jwt-signing-key
 * security.jwt.keystore.key-password=${KEY_PASSWORD}
 */
@Slf4j
@Component
@Profile("prod")
public class KeystoreRsaKeyProvider implements RsaKeyProvider {

    private final String kid;
    private final RSAPublicKey pub;
    private final RSAPrivateKey priv;

    public KeystoreRsaKeyProvider(
            @Value("${security.jwt.kid:prod-rsa-1}") String kid,
            @Value("${security.jwt.keystore.path}") String keystorePath,
            @Value("${security.jwt.keystore.password}") String ksPassword,
            @Value("${security.jwt.keystore.key-alias}") String keyAlias,
            @Value("${security.jwt.keystore.key-password}") String keyPassword) {
        this.kid = kid;
        try (InputStream fis = new FileInputStream(keystorePath)) {
            KeyStore ks = KeyStore.getInstance("PKCS12"); // ✅ Puedes usar JKS si lo prefieres
            ks.load(fis, ksPassword.toCharArray());

            Key key = ks.getKey(keyAlias, keyPassword.toCharArray());
            if (!(key instanceof RSAPrivateKey privKey)) {
                throw new IllegalStateException("Key alias does not reference an RSA private key");
            }

            X509Certificate cert = (X509Certificate) ks.getCertificate(keyAlias);
            if (cert == null) {
                throw new IllegalStateException("No certificate found for alias: " + keyAlias);
            }

            this.priv = privKey;
            this.pub = (RSAPublicKey) cert.getPublicKey();

            log.info("✅ Loaded RSA keypair from keystore: {} (alias='{}')", keystorePath, keyAlias);
        } catch (Exception e) {
            throw new IllegalStateException("❌ Cannot load RSA keys from keystore: " + keystorePath, e);
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
