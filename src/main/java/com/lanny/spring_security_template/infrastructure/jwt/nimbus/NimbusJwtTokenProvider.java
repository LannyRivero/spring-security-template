package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.time.Duration;
import java.util.List;
import java.util.Objects;
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

    // ============================================================
    // TOKEN GENERATION
    // ============================================================

    @Override
    public String generateAccessToken(
            String subject,
            List<String> roles,
            List<String> scopes,
            Duration ttl) {

        return jwtUtils.generateAccessToken(subject, roles, scopes, ttl);
    }

    @Override
    public String generateRefreshToken(String subject, Duration ttl) {
        return jwtUtils.generateRefreshToken(subject, ttl);
    }

    // ============================================================
    // VALIDATION (cryptographic + domain logic)
    // ============================================================

    @Override
    public boolean validateToken(String token) {
        try {
            // Validación completa: firma + claims + reglas de negocio
            jwtValidator.validate(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ============================================================
    // SUBJECT EXTRACTION
    // ============================================================

    @Override
    public String extractSubject(String token) {
        return jwtUtils.validateAndParse(token).getSubject();
    }

    // ============================================================
    // CLAIM PARSING (safe version)
    // ============================================================

    @Override
    public Optional<TokenClaims> parseClaims(String token) {
        try {
            JWTClaimsSet claims = jwtUtils.validateAndParse(token);

            List<String> roles = extractStringListClaim(claims, "roles");
            List<String> scopes = extractStringListClaim(claims, "scopes");
            List<String> aud = claims.getAudience() != null ? claims.getAudience() : List.of();

            return Optional.of(new TokenClaims(
                    claims.getSubject(),
                    roles,
                    scopes,
                    claims.getIssueTime().toInstant().getEpochSecond(),
                    claims.getExpirationTime().toInstant().getEpochSecond(),
                    claims.getJWTID(),
                    claims.getIssuer(),
                    aud));

        } catch (Exception e) {
            return Optional.empty();
        }
    }

    // ============================================================
    // FULL VALIDATION WITH DOMAIN CLAIMS DTO
    // ============================================================

    @Override
    public Optional<JwtClaimsDTO> validateAndGetClaims(String token) {
        try {
            return Optional.of(jwtValidator.validate(token));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    // ============================================================
    // JTI EXTRACTION
    // ============================================================

    @Override
    public String extractJti(String token) {
        try {
            return jwtUtils.validateAndParse(token).getJWTID();
        } catch (Exception e) {
            throw new IllegalArgumentException("Cannot extract jti from token", e);
        }
    }

    // ============================================================
    // SAFE HELPERS (no ParseException)
    // ============================================================

    private List<String> extractStringListClaim(JWTClaimsSet claims, String name) {
        Object raw = claims.getClaim(name);

        if (raw instanceof List<?> list) {
            return list.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .toList();
        }

        return List.of();
    }
}
