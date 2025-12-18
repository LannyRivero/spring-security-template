package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Nimbus-based JWT generator and validator.
 *
 * Responsible for:
 * - Access & Refresh token generation
 * - RSA (RS256) signing
 * - Strict JWT validation (header, signature, claims)
 *
 * Infrastructure-only component.
 */
@Component
public class JwtUtils {

    private final RsaKeyProvider keyProvider;
    private final SecurityJwtProperties props;
    private final ClockProvider clockProvider;

    public JwtUtils(
            RsaKeyProvider keyProvider,
            SecurityJwtProperties props,
            ClockProvider clockProvider) {

        this.keyProvider = keyProvider;
        this.props = props;
        this.clockProvider = clockProvider;
    }

    // ======================================================
    // TOKEN GENERATION
    // ======================================================

    public String generateAccessToken(
            String subject,
            List<String> roles,
            List<String> scopes,
            Duration ttl) {

        return generateToken(subject, roles, scopes, ttl, false);
    }

    public String generateRefreshToken(String subject, Duration ttl) {
        return generateToken(subject, List.of(), List.of(), ttl, true);
    }

    private String generateToken(
            String subject,
            List<String> roles,
            List<String> scopes,
            Duration ttl,
            boolean refresh) {

        try {
            Instant now = clockProvider.now();

            Instant exp = ttl != null
                    ? now.plus(ttl)
                    : now.plus(refresh ? props.refreshTtl() : props.accessTtl());

            String audience = refresh
                    ? Optional.ofNullable(props.refreshAudience())
                            .orElse(props.accessAudience())
                    : props.accessAudience();

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer(props.issuer())
                    .audience(audience)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(exp))
                    .jwtID(UUID.randomUUID().toString());

            if (refresh) {
                claims.claim("type", "refresh");
            } else {
                claims.claim("roles", roles);
                claims.claim("scopes", scopes);
            }

            JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                    .type(JOSEObjectType.JWT)
                    .keyID(keyProvider.keyId())
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(new RSASSASigner((RSAPrivateKey) keyProvider.privateKey()));

            return jwt.serialize();

        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate JWT token", e);
        }
    }

    // ======================================================
    // VALIDATION
    // ======================================================

    public JWTClaimsSet validateAndParse(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);

            validateHeader(jwt);
            validateSignature(jwt);

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            validateClaims(claims);

            return claims;

        } catch (Exception e) {
            throw new SecurityException("Invalid JWT token", e);
        }
    }

    private void validateSignature(SignedJWT jwt) throws JOSEException {
        JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) keyProvider.publicKey());

        if (!jwt.verify(verifier)) {
            throw new JOSEException("Invalid JWT signature");
        }
    }

    // ======================================================
    // HEADER VALIDATION
    // ======================================================

    private void validateHeader(SignedJWT jwt) throws JOSEException {

        if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
            throw new JOSEException("Invalid JWT algorithm");
        }

        if (!JOSEObjectType.JWT.equals(jwt.getHeader().getType())) {
            throw new JOSEException("Invalid JWT type");
        }

        String kid = jwt.getHeader().getKeyID();
        if (kid == null || !kid.equals(keyProvider.keyId())) {
            throw new JOSEException("Invalid or missing JWT key ID (kid)");
        }
    }

    // ======================================================
    // CLAIM VALIDATION
    // ======================================================

    private void validateClaims(JWTClaimsSet claims) throws JOSEException {

        Instant now = clockProvider.now();
        long skew = props.allowedClockSkewSeconds();

        // Expiration
        if (claims.getExpirationTime() == null ||
                claims.getExpirationTime().toInstant()
                        .isBefore(now.minusSeconds(skew))) {
            throw new JOSEException("JWT token expired");
        }

        // Issued At (iat)
        if (claims.getIssueTime() != null) {
            Instant iat = claims.getIssueTime().toInstant();
            if (iat.isAfter(now.plusSeconds(skew))) {
                throw new JOSEException("JWT issued in the future");
            }
        }

        // Not Before (nbf)
        if (claims.getNotBeforeTime() != null &&
                claims.getNotBeforeTime().toInstant()
                        .isAfter(now.plusSeconds(skew))) {
            throw new JOSEException("JWT not valid yet");
        }

        // Issuer
        if (!Objects.equals(claims.getIssuer(), props.issuer())) {
            throw new JOSEException("Invalid JWT issuer");
        }

        // Audience
        String expectedAudience = isRefresh(claims)
                ? Optional.ofNullable(props.refreshAudience())
                        .orElse(props.accessAudience())
                : props.accessAudience();

        List<String> aud = claims.getAudience();
        if (aud == null || !aud.contains(expectedAudience)) {
            throw new JOSEException("Invalid JWT audience");
        }

        validateTokenType(claims);
    }

    private void validateTokenType(JWTClaimsSet claims) throws JOSEException {

        if (isRefresh(claims)) {
            if (claims.getClaim("roles") != null ||
                    claims.getClaim("scopes") != null) {
                throw new JOSEException(
                        "Refresh token must not contain roles or scopes");
            }
        }
    }

    private boolean isRefresh(JWTClaimsSet claims) {
        try {
            return "refresh".equals(claims.getStringClaim("type"));
        } catch (Exception e) {
            return false;
        }
    }

    // ======================================================
    // HELPERS
    // ======================================================

    public boolean isValid(String token) {
        try {
            validateAndParse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public String extractSubject(String token) {
        return validateAndParse(token).getSubject();
    }
}
