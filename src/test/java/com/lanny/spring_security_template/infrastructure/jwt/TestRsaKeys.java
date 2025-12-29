package com.lanny.spring_security_template.infrastructure.jwt;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * Utility for generating RSA keys for unit tests.
 */
public final class TestRsaKeys {

    private TestRsaKeys() {
    }

    public static RsaKeyProvider generate() {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance("RSA");
            gen.initialize(2048);

            KeyPair pair = gen.generateKeyPair();

            RSAPublicKey pub = (RSAPublicKey) pair.getPublic();
            RSAPrivateKey priv = (RSAPrivateKey) pair.getPrivate();

            return new RsaKeyProvider() {

                @Override
                public RSAPrivateKey privateKey() {
                    return priv;
                }

                @Override
                public RSAPublicKey getPublicKey() {
                    return pub;
                }

                @Override
                public String keyId() {
                    return "test-key";
                }

                @Override
                public java.util.Map<String, RSAPublicKey> verificationKeys() {
                    return java.util.Map.of("test-key", pub);
                }

                @Override
                public String activeKid() {
                    return "test-key";
                }
            };

        } catch (Exception e) {
            throw new IllegalStateException("Error generating RSA keys for test", e);
        }
    }
}
