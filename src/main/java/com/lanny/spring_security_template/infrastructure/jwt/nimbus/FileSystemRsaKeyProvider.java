package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

/**
 * ✅ Loads RSA keys from the file system for production environments.
 * Keys are read from secure absolute paths, defined in configuration.
 */
@Slf4j
@Component
@Profile("prod")
public class FileSystemRsaKeyProvider implements KeyProvider {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public FileSystemRsaKeyProvider(
            @Value("${security.jwt.rsa.private-key-location}") String privateKeyPath,
            @Value("${security.jwt.rsa.public-key-location}") String publicKeyPath) {
        this.privateKey = loadPrivateKey(privateKeyPath);
        this.publicKey = loadPublicKey(publicKeyPath);
        log.info("🔐 Loaded RSA keys from filesystem [private={}, public={}]", privateKeyPath, publicKeyPath);
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    private RSAPrivateKey loadPrivateKey(String filePath) {
        try {
            String keyPem = Files.readString(Path.of(filePath))
                    .replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(keyPem);
            var keySpec = new PKCS8EncodedKeySpec(keyBytes);
            return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(keySpec);
        } catch (IOException e) {
            log.error("❌ Failed to read RSA private key from {}", filePath, e);
            throw new IllegalStateException("Could not read RSA private key", e);
        } catch (Exception e) {
            throw new IllegalStateException("Error parsing RSA private key", e);
        }
    }

    private RSAPublicKey loadPublicKey(String filePath) {
        try {
            String keyPem = Files.readString(Path.of(filePath))
                    .replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
            byte[] keyBytes = Base64.getDecoder().decode(keyPem);
            var keySpec = new X509EncodedKeySpec(keyBytes);
            return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(keySpec);
        } catch (IOException e) {
            log.error("❌ Failed to read RSA public key from {}", filePath, e);
            throw new IllegalStateException("Could not read RSA public key", e);
        } catch (Exception e) {
            throw new IllegalStateException("Error parsing RSA public key", e);
        }
    }
}
