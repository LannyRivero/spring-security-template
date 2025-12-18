package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.config.JwtAlgorithm;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Nimbus-based JWT generator and validator.
 *
 * <p>
 * Supports Access and Refresh tokens with strict validation of:
 * algorithm, kid, signature, issuer, audience, temporal claims and token type.
 * </p>
 *
 * <p>
 * Token type is expressed via the {@code token_use} claim:
 * {@code access} or {@code refresh}.
 * </p>
 */
@Component
public class JwtUtils {

    private static final String CLAIM_TOKEN_USE = "token_use";
    private static final String TOKEN_USE_ACCESS = "access";
    private static final String TOKEN_USE_REFRESH = "refresh";

    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_SCOPES = "scopes";

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
                    ? Optional.ofNullable(props.refreshAudience()).orElse(props.accessAudience())
                    : props.accessAudience();

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer(props.issuer())
                    .audience(audience)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(exp))
                    .jwtID(UUID.randomUUID().toString());

            // Token type ALWAYS present
            if (refresh) {
                claims.claim(CLAIM_TOKEN_USE, TOKEN_USE_REFRESH);
                // Refresh tokens must not include roles/scopes
            } else {
                claims.claim(CLAIM_TOKEN_USE, TOKEN_USE_ACCESS);
                claims.claim(CLAIM_ROLES, roles);
                claims.claim(CLAIM_SCOPES, scopes);
            }

            JWSAlgorithm alg = resolveJwsAlgorithm();
            JWSHeader header = new JWSHeader.Builder(alg)
                    .type(JOSEObjectType.JWT)
                    .keyID(keyProvider.keyId())
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(resolveSigner());

            return jwt.serialize();

        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate JWT token", e);
        }
    }

    // ======================================================
    // VALIDATION (GENERIC)
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

    // ======================================================
    // VALIDATION (SEMANTIC)
    // ======================================================

    public JWTClaimsSet validateAccessToken(String token) {
        JWTClaimsSet claims = validateAndParse(token);
        validateTokenUse(claims, TOKEN_USE_ACCESS);


        Object roles = claims.getClaim(CLAIM_ROLES);
        Object scopes = claims.getClaim(CLAIM_SCOPES);
        if (roles == null && scopes == null) {
            throw new SecurityException("Access token must contain roles and/or scopes");
        }
        return claims;
    }

    public JWTClaimsSet validateRefreshToken(String token) {
        JWTClaimsSet claims = validateAndParse(token);
        validateTokenUse(claims, TOKEN_USE_REFRESH);

        // Refresh tokens must not carry roles/scopes
        if (claims.getClaim(CLAIM_ROLES) != null || claims.getClaim(CLAIM_SCOPES) != null) {
            throw new SecurityException("Refresh token must not contain roles or scopes");
        }
        return claims;
    }

    private void validateTokenUse(JWTClaimsSet claims, String expected) {
        try {
            String tokenUse = claims.getStringClaim(CLAIM_TOKEN_USE);
            if (!expected.equals(tokenUse)) {
                throw new SecurityException("Invalid token type: expected " + expected);
            }
        } catch (Exception e) {
            throw new SecurityException("Missing or invalid token_use claim", e);
        }
    }

    // ======================================================
    // SIGNATURE VALIDATION
    // ======================================================

    private void validateSignature(SignedJWT jwt) throws JOSEException {
        JWSVerifier verifier = resolveVerifier();

        if (!jwt.verify(verifier)) {
            throw new JOSEException("Invalid JWT signature");
        }
    }

    // ======================================================
    // HEADER VALIDATION
    // ======================================================

    private void validateHeader(SignedJWT jwt) throws JOSEException {

        JWSAlgorithm expectedAlg = resolveJwsAlgorithm();
        if (!expectedAlg.equals(jwt.getHeader().getAlgorithm())) {
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
                claims.getExpirationTime().toInstant().isBefore(now.minusSeconds(skew))) {
            throw new JOSEException("JWT token expired");
        }

        // Issued At (iat)
        if (claims.getIssueTime() != null) {
            Instant iat = claims.getIssueTime().toInstant();
            if (iat.isAfter(now.plusSeconds(skew))) {
                throw new JOSEException("JWT issued in the future");
            }
        }

        // Not Before (nbf) - optional
        if (claims.getNotBeforeTime() != null &&
                claims.getNotBeforeTime().toInstant().isAfter(now.plusSeconds(skew))) {
            throw new JOSEException("JWT not valid yet");
        }

        // Issuer
        if (!Objects.equals(claims.getIssuer(), props.issuer())) {
            throw new JOSEException("Invalid JWT issuer");
        }

        // Audience based on token_use
        String expectedAudience = isRefresh(claims)
                ? Optional.ofNullable(props.refreshAudience()).orElse(props.accessAudience())
                : props.accessAudience();

        List<String> aud = claims.getAudience();
        if (aud == null || !aud.contains(expectedAudience)) {
            throw new JOSEException("Invalid JWT audience");
        }

        // Token type must exist
        validateTokenUsePresent(claims);
    }

    private void validateTokenUsePresent(JWTClaimsSet claims) throws JOSEException {
        try {
            String tokenUse = claims.getStringClaim(CLAIM_TOKEN_USE);
            if (!TOKEN_USE_ACCESS.equals(tokenUse) && !TOKEN_USE_REFRESH.equals(tokenUse)) {
                throw new JOSEException("Invalid token_use claim");
            }
        } catch (Exception e) {
            throw new JOSEException("Missing token_use claim", e);
        }
    }

    private boolean isRefresh(JWTClaimsSet claims) {
        try {
            return TOKEN_USE_REFRESH.equals(claims.getStringClaim(CLAIM_TOKEN_USE));
        } catch (Exception e) {
            return false;
        }
    }

    // ======================================================
    // STRATEGY: ALGORITHM / SIGNER / VERIFIER
    // ======================================================

    private JWSAlgorithm resolveJwsAlgorithm() {
        return props.algorithm() == JwtAlgorithm.HMAC ? JWSAlgorithm.HS256 : JWSAlgorithm.RS256;
    }

    private JWSSigner resolveSigner() throws KeyLengthException {
        if (props.algorithm() == JwtAlgorithm.HMAC) {
            return new MACSigner(resolveHmacSecretBytes());
        }
        return new RSASSASigner((RSAPrivateKey) keyProvider.privateKey());
    }

    private JWSVerifier resolveVerifier() throws JOSEException {
        if (props.algorithm() == JwtAlgorithm.HMAC) {
            return new MACVerifier(resolveHmacSecretBytes());
        }
        return new RSASSAVerifier((RSAPublicKey) keyProvider.publicKey());
    }

    /**
     * Resolves HMAC secret bytes (Base64) from configuration.
     *
     * <p>
     * Adjust this method to match your exact properties structure
     * (e.g. props.hmac().secretBase64()).
     * </p>
     */
    private byte[] resolveHmacSecretBytes() {
        // ✅ Ajusta esta línea según tu record/properties real:
        // Example expected: props.hmac().secretBase64()
        String base64 = props.hmac().secretBase64();

        // Nimbus requires enough key length (>= 256 bits for HS256)
        return Base64.getDecoder().decode(base64.getBytes(StandardCharsets.UTF_8));
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
