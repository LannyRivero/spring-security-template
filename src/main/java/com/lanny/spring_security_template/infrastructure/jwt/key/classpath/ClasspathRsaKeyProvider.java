package com.lanny.spring_security_template.infrastructure.jwt.key.classpath;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Loads RSA keys from the classpath.
 * 
 * Used for development and testing environments.
 */
@Component
@Profile({ "dev", "test" })
public class ClasspathRsaKeyProvider implements RsaKeyProvider {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public ClasspathRsaKeyProvider() {
        this.privateKey = PemUtils.readPrivateKey("/keys/rsa-private.pem");
        this.publicKey = PemUtils.readPublicKey("/keys/rsa-public.pem");
    }

    @Override
    public String keyId() {
        return "classpath-dev-key";
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
