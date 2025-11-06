package com.lanny.spring_security_template.infrastructure.jwt.key;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA Key Provider abstraction.
 *
 * Provides RSA key pairs for JWT signing and verification.
 * 
 * Each provider defines its own key source (classpath, file system, cloud KMS,
 * etc.)
 * and may expose a key ID (kid) for token header identification and rotation.
 */
public interface RsaKeyProvider {

    /** Unique key identifier (useful for rotation / header kid). */
    String keyId();

    /** Public key used for signature verification. */
    RSAPublicKey publicKey();

    /** Private key used for token signing. */
    RSAPrivateKey privateKey();
}
