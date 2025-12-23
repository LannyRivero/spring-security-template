package com.lanny.spring_security_template.infrastructure.jwt.key;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import java.util.Optional;

/**
 * RSA Key Provider abstraction supporting key rotation (multi-kid).
 */
public interface RsaKeyProvider {

    /** Kid of the active signing key (used to issue new tokens). */
    String activeKid();

    /** Private key used to sign new tokens (active). */
    RSAPrivateKey privateKey();

    /** Public keys accepted for verification. Key = kid. */
    Map<String, RSAPublicKey> verificationKeys();

    default Optional<RSAPublicKey> findPublicKey(String kid) {
        return Optional.ofNullable(verificationKeys().get(kid));
    }
}

