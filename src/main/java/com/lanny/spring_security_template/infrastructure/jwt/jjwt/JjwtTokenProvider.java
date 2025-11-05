package com.lanny.spring_security_template.infrastructure.jwt.jjwt;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.KeyProvider;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Component
@ConditionalOnProperty(name = "security.jwt.provider", havingValue = "jjwt")
public class JjwtTokenProvider implements TokenProvider {

    private final KeyProvider keyProvider;
    private final String issuer;
    private final String audience;

    public JjwtTokenProvider(
            KeyProvider keyProvider,
            @Value("${security.jwt.issuer}") String issuer,
            @Value("${security.jwt.audience}") String audience) {
        this.keyProvider = keyProvider;
        this.issuer = issuer;
        this.audience = audience;
    }

    @Override
    public String generateAccessToken(String subject, List<String> roles, List<String> scopes, Duration ttl) {
        Instant now = Instant.now();
        Instant exp = now.plus(ttl);
        return Jwts.builder()
                .subject(subject)
                .issuer(issuer)
                .audience().add(audience).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .id(UUID.randomUUID().toString())
                .claim("roles", roles)
                .claim("scopes", scopes)
                .signWith((RSAPrivateKey) keyProvider.getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    @Override
    public String generateRefreshToken(String subject, Duration ttl) {
        Instant now = Instant.now();
        Instant exp = now.plus(ttl);
        return Jwts.builder()
                .subject(subject)
                .issuer(issuer)
                .audience().add(audience).and()
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .id(UUID.randomUUID().toString())
                .claim("type", "refresh")
                .signWith((RSAPrivateKey) keyProvider.getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .verifyWith((RSAPublicKey) keyProvider.getPublicKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public String extractSubject(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith((RSAPublicKey) keyProvider.getPublicKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();
            return claims.getSubject();
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid JWT: " + e.getMessage(), e);
        }
    }

    @Override
    public Optional<TokenClaims> parseClaims(String token) {
        try {
            Claims claims = Jwts.parser()
                    .verifyWith((RSAPublicKey) keyProvider.getPublicKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // Safe extraction helpers
            @SuppressWarnings("unchecked")
            List<String> roles = claims.get("roles", List.class) != null
                    ? (List<String>) claims.get("roles", List.class)
                    : List.of();

            @SuppressWarnings("unchecked")
            List<String> scopes = claims.get("scopes", List.class) != null
                    ? (List<String>) claims.get("scopes", List.class)
                    : List.of();

            Set<String> aud = Optional.ofNullable(claims.getAudience()).orElse(Set.of(audience));

            return Optional.of(new TokenClaims(
                    claims.getSubject(),
                    roles,
                    scopes,
                    claims.getIssuedAt().toInstant().getEpochSecond(),
                    claims.getExpiration().toInstant().getEpochSecond(),
                    claims.getId(),
                    claims.getIssuer(),
                    new ArrayList<>(aud)));

        } catch (JwtException e) {
            return Optional.empty();
        }
    }

}
