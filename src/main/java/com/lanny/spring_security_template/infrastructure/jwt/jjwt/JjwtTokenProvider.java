package com.lanny.spring_security_template.infrastructure.jwt.jjwt;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.KeyProvider;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.JwtException;


@Component
@ConditionalOnProperty(name = "security.jwt.provider", havingValue = "jjwt")
public class JjwtTokenProvider implements TokenProvider {

    private final KeyProvider keyProvider;

    public JjwtTokenProvider(KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    @Override
    public String generateAccessToken(String subject, List<String> roles, List<String> scopes) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(3600))) 
                .claim("roles", roles)
                .claim("scopes", scopes)
                .signWith(keyProvider.getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    @Override
    public String generateRefreshToken(String subject) {
        Instant now = Instant.now();
        return Jwts.builder()
                .subject(subject)
                .issuedAt(Date.from(now))
                .expiration(Date.from(now.plusSeconds(604800))) 
                .claim("type", "refresh")
                .signWith(keyProvider.getPrivateKey(), Jwts.SIG.RS256)
                .compact();
    }

    @Override
    public boolean validateToken(String token) {
        try {
            JwtParser parser = Jwts.parser()
                    .verifyWith(keyProvider.getPublicKey())
                    .build();
            parser.parseSignedClaims(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    @Override
    public String extractSubject(String token) {
        try {
            JwtParser parser = Jwts.parser()
                    .verifyWith(keyProvider.getPublicKey())
                    .build();
            Claims claims = parser.parseSignedClaims(token).getPayload();
            return claims.getSubject();
        } catch (JwtException e) {
            throw new IllegalArgumentException("Invalid JWT: " + e.getMessage(), e);
        }
    }
}
