package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
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
    private final JwtValidator jwtValidator;

    public NimbusJwtTokenProvider(JwtUtils jwtUtils, JwtValidator jwtValidator) {
        this.jwtUtils = jwtUtils;
        this.jwtValidator = jwtValidator;
    }

    @Override
    public String generateAccessToken(String subject,
            List<String> roles,
            List<String> scopes,
            Duration ttl) {
        return jwtUtils.generateToken(subject, roles, scopes, ttl, false);
    }

    @Override
    public String generateRefreshToken(String subject, Duration ttl) {
        return jwtUtils.generateToken(subject, Collections.emptyList(), Collections.emptyList(), ttl, true);
    }

    @Override
    public boolean validateToken(String token) {
        return parseClaims(token).isPresent();
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
                    claims.getStringListClaim("roles") != null ? claims.getStringListClaim("roles") : List.of(),
                    claims.getStringListClaim("scopes") != null ? claims.getStringListClaim("scopes") : List.of(),
                    claims.getIssueTime().toInstant().getEpochSecond(),
                    claims.getExpirationTime().toInstant().getEpochSecond(),
                    claims.getJWTID(),
                    claims.getIssuer(),
                    claims.getStringListClaim("aud") != null ? claims.getStringListClaim("aud") : List.of()));

        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<JwtClaimsDTO> validateAndGetClaims(String token) {
        try {
            JwtClaimsDTO dto = jwtValidator.validate(token);
            return Optional.of(dto);
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public String extractJti(String token) {
        try {
            var claims = jwtUtils.validateAndParse(token);
            return claims.getJWTID();
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot extract jti from token", e);
        }
    }

}
