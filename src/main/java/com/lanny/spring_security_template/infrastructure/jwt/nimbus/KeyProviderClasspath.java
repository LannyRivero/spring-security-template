package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

@Component
@Profile({ "dev", "test" })
public class KeyProviderClasspath implements ClasspathRsaKeyProvider {

    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public KeyProviderClasspath() {
        this.privateKey = PemUtils.readPrivateKey("/keys/rsa-private.pem");
        this.publicKey = PemUtils.readPublicKey("/keys/rsa-public.pem");
    }

    @Override
    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }

    @Override
    public RSAPublicKey getPublicKey() {
        return publicKey;
    }
}
