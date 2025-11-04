package com.lanny.spring_security_template.infrastructure.jwt;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import org.springframework.stereotype.Component;

import java.security.interfaces.*;
import java.time.Instant;
import java.util.*;

@Component
public class JwtUtils {

    private final KeyProvider keyProvider;

    public JwtUtils(KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    public String generateAccessToken(String subject, List<String> roles, List<String> scopes) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer("spring-security-template")
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(900)))
                    .claim("roles", roles)
                    .claim("scopes", scopes)
                    .claim("jti", UUID.randomUUID().toString())
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .keyID("dev-key")
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner((RSAPrivateKey) keyProvider.getPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Error creating access token", e);
        }
    }

    public String generateRefreshToken(String subject) {
        try {
            Instant now = Instant.now();
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer("spring-security-template")
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(2592000))) // 30 días
                    .claim("type", "refresh")
                    .build();

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                    claims);
            jwt.sign(new RSASSASigner((RSAPrivateKey) keyProvider.getPrivateKey()));
            return jwt.serialize();
        } catch (Exception e) {
            throw new IllegalStateException("Error creating refresh token", e);
        }
    }

    public JWTClaimsSet validateAndParse(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) keyProvider.getPublicKey());
            if (!jwt.verify(verifier))
                throw new JOSEException("Invalid signature");

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (claims.getExpirationTime().before(new Date()))
                throw new JOSEException("Token expired");

            return claims;
        } catch (Exception e) {
            throw new RuntimeException("Invalid token: " + e.getMessage(), e);
        }
    }
}
