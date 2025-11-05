package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

@Component
@ConditionalOnProperty(name = "security.jwt.provider", havingValue = "nimbus", matchIfMissing = true)
public class NimbusJwtTokenProvider implements TokenProvider {

    private final JwtUtils jwtUtils;

    public NimbusJwtTokenProvider(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public String generateAccessToken(String subject, List<String> roles, List<String> scopes, Duration ttl) {
        return jwtUtils.generateToken(subject, roles, scopes, ttl, false);
    }

    @Override
    public String generateRefreshToken(String subject, Duration ttl) {
        return jwtUtils.generateToken(subject, Collections.emptyList(), Collections.emptyList(), ttl, true);
    }

    @Override
    public boolean validateToken(String token) {
        try {
            jwtUtils.validateAndParse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String extractSubject(String token) {
        return jwtUtils.validateAndParse(token).getSubject();
    }

    @Override
    public Optional<TokenClaims> parseClaims(String token) {
        try {
            JWTClaimsSet claims = jwtUtils.validateAndParse(token);
            return Optional.of(new TokenClaims(
                claims.getSubject(),
                claims.getStringListClaim("roles"),
                claims.getStringListClaim("scopes"),
                claims.getIssueTime().toInstant().getEpochSecond(),
                claims.getExpirationTime().toInstant().getEpochSecond(),
                claims.getJWTID(),
                claims.getIssuer(),
                claims.getStringListClaim("aud") != null ? claims.getStringListClaim("aud") : List.of()
            ));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
