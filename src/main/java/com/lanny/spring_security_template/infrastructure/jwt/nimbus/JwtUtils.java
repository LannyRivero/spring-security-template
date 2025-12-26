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
import com.lanny.spring_security_template.infrastructure.config.JwtAlgorithm;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.exception.JwtValidationException;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Low-level JWT utility based on Nimbus JOSE + JWT.
 *
 * <p>
 * Responsibilities:
 * <ul>
 * <li>Token generation (access / refresh)</li>
 * <li>Cryptographic validation</li>
 * <li>Structural and temporal claim validation</li>
 * </ul>
 *
 * <p>
 * This class performs NO authorization decisions; it only handles token generation
 * and low-level validation. Semantic meaning and authorization logic are handled
 * by higher layers.
 *
 * IMPORTANT:
 * Do not use this class directly for authorization decisions; use
 * JwtValidator or StrictJwtValidator instead.
 */
@Component
public final class JwtUtils {

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
                    .jwtID(UUID.randomUUID().toString())
                    .claim(CLAIM_TOKEN_USE, refresh ? TOKEN_USE_REFRESH : TOKEN_USE_ACCESS);

            if (!refresh) {
                claims.claim(CLAIM_ROLES, roles);
                claims.claim(CLAIM_SCOPES, scopes);
            }

            JWSHeader header = new JWSHeader.Builder(resolveJwsAlgorithm())
                    .type(JOSEObjectType.JWT)
                    .keyID(keyProvider.activeKid())
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(resolveSigner());

            return jwt.serialize();

        } catch (Exception e) {
            throw new IllegalStateException("JWT generation failed", e);
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
            throw new JwtValidationException(e);
        }
    }

    // ======================================================
    // INTERNAL VALIDATION STEPS
    // ======================================================

    private void validateHeader(SignedJWT jwt) throws JOSEException {

        if (!resolveJwsAlgorithm().equals(jwt.getHeader().getAlgorithm())) {
            throw new JOSEException("alg");
        }

        if (!JOSEObjectType.JWT.equals(jwt.getHeader().getType())) {
            throw new JOSEException("typ");
        }

        if (jwt.getHeader().getKeyID() == null || jwt.getHeader().getKeyID().isBlank()) {
            throw new JOSEException("kid");
        }
    }

    private void validateSignature(SignedJWT jwt) throws JOSEException {

        JWSVerifier verifier = resolveVerifier(jwt.getHeader().getKeyID());

        if (!jwt.verify(verifier)) {
            throw new JOSEException("sig");
        }
    }

    private void validateClaims(JWTClaimsSet claims) throws JOSEException {

        Instant now = clockProvider.now();
        long skew = props.allowedClockSkewSeconds();

        if (claims.getExpirationTime() == null ||
                claims.getExpirationTime().toInstant().isBefore(now.minusSeconds(skew))) {
            throw new JOSEException("exp");
        }

        if (claims.getIssueTime() != null &&
                claims.getIssueTime().toInstant().isAfter(now.plusSeconds(skew))) {
            throw new JOSEException("iat");
        }

        if (claims.getNotBeforeTime() != null &&
                claims.getNotBeforeTime().toInstant().isAfter(now.plusSeconds(skew))) {
            throw new JOSEException("nbf");
        }

        if (!Objects.equals(claims.getIssuer(), props.issuer())) {
            throw new JOSEException("iss");
        }

        String tokenUseValue;
        try {
            tokenUseValue = claims.getStringClaim(CLAIM_TOKEN_USE);
        } catch (java.text.ParseException e) {
            throw new JOSEException("token_use", e);
        }

        String expectedAudience = TOKEN_USE_REFRESH.equals(tokenUseValue)
                ? Optional.ofNullable(props.refreshAudience()).orElse(props.accessAudience())
                : props.accessAudience();

        if (claims.getAudience() == null || !claims.getAudience().contains(expectedAudience)) {
            throw new JOSEException("aud");
        }

        validateTokenUsePresent(claims);
    }

    private void validateTokenUsePresent(JWTClaimsSet claims) throws JOSEException {
        String tokenUse;
        try {
            tokenUse = claims.getStringClaim(CLAIM_TOKEN_USE);
        } catch (java.text.ParseException e) {
            throw new JOSEException("token_use", e);
        }
        if (!TOKEN_USE_ACCESS.equals(tokenUse) && !TOKEN_USE_REFRESH.equals(tokenUse)) {
            throw new JOSEException("token_use");
        }
    }

    // ======================================================
    // CRYPTO STRATEGY
    // ======================================================

    private JWSAlgorithm resolveJwsAlgorithm() {
        return props.algorithm() == JwtAlgorithm.HMAC
                ? JWSAlgorithm.HS256
                : JWSAlgorithm.RS256;
    }

    private JWSSigner resolveSigner() throws KeyLengthException {
        if (props.algorithm() == JwtAlgorithm.HMAC) {
            return new MACSigner(resolveHmacSecretBytes());
        }
        return new RSASSASigner((RSAPrivateKey) keyProvider.privateKey());
    }

    private JWSVerifier resolveVerifier(String kid) throws JOSEException {
        if (props.algorithm() == JwtAlgorithm.HMAC) {
            return new MACVerifier(resolveHmacSecretBytes());
        }

        RSAPublicKey pub = keyProvider.findPublicKey(kid)
                .orElseThrow(() -> new JOSEException("kid"));

        return new RSASSAVerifier(pub);
    }

    private byte[] resolveHmacSecretBytes() {
        return Base64.getDecoder()
                .decode(props.hmac().secretBase64().getBytes(StandardCharsets.UTF_8));
    }

    // ======================================================
    // HELPERS (⚠️ NOT FOR AUTHORIZATION)
    // ======================================================

    /**
     * ⚠️ Technical validation only.
     * Do NOT use for authorization decisions.
     */
    public boolean isValid(String token) {
        try {
            validateAndParse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * ⚠️ Extracts subject without authorization checks.
     */
    public String extractSubject(String token) {
        return validateAndParse(token).getSubject();
    }
}
