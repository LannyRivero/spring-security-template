package com.lanny.spring_security_template.infrastructure.jwt;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public interface KeyProvider {
    RSAPrivateKey getPrivateKey();
    
    RSAPublicKey getPublicKey();
}
