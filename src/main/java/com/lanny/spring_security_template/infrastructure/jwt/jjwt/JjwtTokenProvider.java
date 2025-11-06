package com.lanny.spring_security_template.infrastructure.jwt.jjwt;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.*;

@Component
@ConditionalOnProperty(name = "security.jwt.provider", havingValue = "jjwt", matchIfMissing = true)
public class JjwtTokenProvider implements TokenProvider {

    private final RsaKeyProvider keyProvider;
    private final SecurityJwtProperties props;

    public JjwtTokenProvider(RsaKeyProvider keyProvider, SecurityJwtProperties props) {
        this.keyProvider = keyProvider;
        this.props = props;
    }

    @Override
    public String generateAccessToken(String subject, List<String> roles, List<String> scopes, Duration ttl) {
        return buildToken(subject, roles, scopes, ttl, props.accessAudience(), Map.of());
    }

    @Override
    public String generateRefreshToken(String subject, Duration ttl) {
        return buildToken(subject, List.of(), List.of(), ttl, props.refreshAudience(), Map.of("type", "refresh"));
    }

    @Override
    public boolean validateToken(String token) {
        try {
            Jwts.parser()
                    .requireIssuer(props.issuer())
                    .verifyWith((RSAPublicKey) keyProvider.publicKey())
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    @Override
    public String extractSubject(String token) {
        return parseClaims(token)
                .map(TokenClaims::sub)
                .orElseThrow(() -> new IllegalArgumentException("Invalid JWT: cannot extract subject"));
    }

    @Override
    public Optional<TokenClaims> parseClaims(String token) {
        try {
            var claims = Jwts.parser()
                    .requireIssuer(props.issuer())
                    .verifyWith((RSAPublicKey) keyProvider.publicKey())
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            List<String> roles = safeStringList(claims.get("roles"));
            List<String> scopes = safeStringList(claims.get("scopes"));
            List<String> aud = new ArrayList<>(Optional.ofNullable(claims.getAudience()).orElse(Set.of()));

            return Optional.of(new TokenClaims(
                    claims.getSubject(),
                    roles,
                    scopes,
                    claims.getIssuedAt().toInstant().getEpochSecond(),
                    claims.getExpiration().toInstant().getEpochSecond(),
                    claims.getId(),
                    claims.getIssuer(),
                    aud));

        } catch (JwtException e) {
            return Optional.empty();
        }
    }

    private static List<String> safeStringList(Object value) {
        if (value instanceof List<?>) {
            List<?> list = (List<?>) value;
            List<String> result = new ArrayList<>();
            for (Object item : list) {
                if (item instanceof String s) {
                    result.add(s);
                }
            }
            return result;
        }
        return List.of();
    }

    private String buildToken(
            String subject,
            List<String> roles,
            List<String> scopes,
            Duration ttl,
            String audience,
            Map<String, Object> extraClaims) {

        Instant now = Instant.now();
        Instant exp = now.plus(ttl);
        String jti = UUID.randomUUID().toString();

        var builder = Jwts.builder()
                .subject(subject)
                .issuer(props.issuer())
                .id(jti)
                .issuedAt(Date.from(now))
                .expiration(Date.from(exp))
                .audience().add(audience).and()
                .claim("roles", roles)
                .claim("scopes", scopes);

        extraClaims.forEach(builder::claim);

        // 🔑 añade KID al header (para rotación de claves RSA)
        builder.header().add("kid", keyProvider.keyId()).and();

        return builder.signWith((RSAPrivateKey) keyProvider.privateKey(), Jwts.SIG.RS256).compact();
    }
}
