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

/**
 * {@code NimbusJwtTokenProvider}
 *
 * <p>
 * Infrastructure adapter that provides JWT generation and validation
 * using the Nimbus JOSE + JWT library.
 * </p>
 *
 * <p>
 * This component bridges low-level cryptographic concerns
 * ({@link JwtUtils}) with domain-level validation rules
 * ({@link JwtValidator}), exposing a safe and controlled API
 * to the application layer.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Generate access and refresh tokens</li>
 * <li>Validate tokens cryptographically and semantically</li>
 * <li>Expose validated domain-level claims</li>
 * </ul>
 *
 * <p>
 * Designed for stateless, production-grade systems requiring
 * strong separation between cryptography and business rules.
 * </p>
 */
@Component
@ConditionalOnProperty(name = "security.jwt.provider", havingValue = "nimbus", matchIfMissing = true)
public class NimbusJwtTokenProvider implements TokenProvider {

    private final JwtUtils jwtUtils;
    private final JwtValidator jwtValidator;

    public NimbusJwtTokenProvider(
            JwtUtils jwtUtils,
            JwtValidator jwtValidator) {
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
    public String generateRefreshToken(
            String subject,
            Duration ttl) {

        return jwtUtils.generateRefreshToken(subject, ttl);
    }

    // ============================================================
    // VALIDATION (single source of truth)
    // ============================================================

    @Override
    public boolean validateToken(String token) {
        return validateAndGetClaims(token).isPresent();
    }

    @Override
    public Optional<JwtClaimsDTO> validateAndGetClaims(String token) {
        try {
            return Optional.of(jwtValidator.validate(token));
        } catch (Exception ex) {
            return Optional.empty();
        }
    }

    // ============================================================
    // SAFE EXTRACTION (validated tokens only)
    // ============================================================

    @Override
    public String extractSubject(String token) {
        try {
            JWTClaimsSet claims = jwtUtils.validateAndParse(token);
            String subject = claims.getSubject();

            if (subject == null || subject.isBlank()) {
                throw new IllegalArgumentException("JWT subject (sub) claim is missing or blank");
            }
            return subject;
        } catch (Exception ex) {
            throw new IllegalArgumentException("Invalid JWT token", ex);
        }
    }

    @Override
    public String extractJti(String token) {
        try {
            JWTClaimsSet claims = jwtUtils.validateAndParse(token);

            String jti = claims.getJWTID();

            if (jti == null || jti.isBlank()) {
                throw new IllegalArgumentException("JWT token does not contain a non-blank jti (JWT ID) claim");
            }
            return jti;
        } catch (Exception ex) {
                throw new IllegalArgumentException("Invalid JWT token", ex);
        }
    }

    // ============================================================
    // BEST-EFFORT PARSING (NON-AUTH USE)
    // ============================================================

    /**
     * Attempts to parse token claims without enforcing domain-level
     * authorization rules.
     *
     * <p>
     * This method MUST NOT be used for authentication or authorization.
     * It is intended only for diagnostics or non-security-critical flows.
     * </p>
     */
    @Override
    public Optional<TokenClaims> parseClaims(String token) {
        try {
            JWTClaimsSet claims = jwtUtils.validateAndParse(token);

            return Optional.of(new TokenClaims(
                    claims.getSubject(),
                    extractStringListClaim(claims, "roles"),
                    extractStringListClaim(claims, "scopes"),
                    claims.getIssueTime().toInstant().getEpochSecond(),
                    claims.getExpirationTime().toInstant().getEpochSecond(),
                    claims.getJWTID(),
                    claims.getIssuer(),
                    claims.getAudience() != null ? claims.getAudience() : List.of()));

        } catch (Exception ex) {
            return Optional.empty();
        }
    }

    // ============================================================
    // INTERNAL HELPERS
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
