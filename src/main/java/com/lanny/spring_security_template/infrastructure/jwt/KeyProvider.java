package com.lanny.spring_security_template.infrastructure.jwt;

import java.security.Key;

public interface KeyProvider {
    Key getPrivateKey();

    Key getPublicKey();
}
