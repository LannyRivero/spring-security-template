package com.lanny.spring_security_template.infrastructure.jwt.key.file;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Loads RSA keys from the file system.
 *
 * Used in production environments (e.g. /opt/keys/).
 */
@Component
@Profile("prod")
public class FileSystemRsaKeyProvider implements RsaKeyProvider {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public FileSystemRsaKeyProvider(
            @Value("${security.jwt.rsa.private-key-location}") String privateKeyPath,
            @Value("${security.jwt.rsa.public-key-location}") String publicKeyPath) {
        this.privateKey = PemUtils.readPrivateKey(privateKeyPath);
        this.publicKey = PemUtils.readPublicKey(publicKeyPath);
    }

    @Override
    public String keyId() {
        return "file-prod-key";
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
