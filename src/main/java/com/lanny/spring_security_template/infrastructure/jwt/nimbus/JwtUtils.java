package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.*;
import com.nimbusds.jwt.*;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.interfaces.*;
import java.time.Instant;
import java.util.*;

@Component
public class JwtUtils {

    private final KeyProvider keyProvider;
  
    private final String issuer;
    private final String audience;
    private final long accessExpiration;
    private final long refreshExpiration;

    public JwtUtils(
            KeyProvider keyProvider,
            @Value("${security.jwt.issuer}") String issuer,
            @Value("${security.jwt.audience}") String audience,

            @Value("${security.jwt.expiration-seconds}") long accessExpiration,
            @Value("${security.jwt.refresh-expiration-seconds:2592000}") long refreshExpiration
    ) {
        this.keyProvider = keyProvider;
        this.issuer = issuer;
        this.audience = audience;
        this.accessExpiration = accessExpiration;
        this.refreshExpiration = refreshExpiration;
    }

    public String generateAccessToken(String subject, List<String> roles, List<String> scopes) {
        try {
            Instant now = Instant.now();

            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer(issuer)
                    .audience(audience)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(accessExpiration)))
                    .claim("roles", roles)
                    .claim("scopes", scopes)
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims);
            jwt.sign(new RSASSASigner(keyProvider.getPrivateKey()));
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
                    .issuer(issuer)
                    .audience(audience)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(now.plusSeconds(refreshExpiration)))
                    .claim("type", "refresh")
                    .jwtID(UUID.randomUUID().toString())
                    .build();

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(),
                    claims
            );

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

            Date now = new Date();
            if (claims.getExpirationTime().before(now))
                throw new JOSEException("Token expired");

            if (!Objects.equals(claims.getIssuer(), issuer))
                throw new JOSEException("Invalid issuer");

            if (claims.getAudience() != null && !claims.getAudience().contains(audience))
                throw new JOSEException("Invalid audience");

            return claims;

        } catch (Exception e) {
            throw new RuntimeException("Invalid token: " + e.getMessage(), e);
        }
    }
}
