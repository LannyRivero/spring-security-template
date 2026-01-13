package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.domain.time.ClockProvider;
import com.lanny.spring_security_template.infrastructure.config.JwtAlgorithm;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.exception.JwtValidationException;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * JwtUtils
 *
 * <p>
 * Low-level JWT utility based on Nimbus JOSE + JWT.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>JWT generation (access / refresh)</li>
 * <li>Cryptographic validation (signature, alg, kid, typ)</li>
 * <li>Temporal validation (exp, iat, nbf with clock skew)</li>
 * </ul>
 *
 * <h2>Explicitly NOT responsible for</h2>
 * <ul>
 * <li>Issuer validation (iss)</li>
 * <li>Audience validation (aud)</li>
 * <li>token_use semantics</li>
 * <li>Authorization or role semantics</li>
 * </ul>
 *
 * <p>
 * Role and scope normalization to framework-specific authorities
 * MUST be handled by the consumer layer (e.g. {@code JwtAuthoritiesMapper}).
 * </p>
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
    private final ClockProvider clock;

    public JwtUtils(
            RsaKeyProvider keyProvider,
            SecurityJwtProperties props,
            ClockProvider clock) {
        this.keyProvider = keyProvider;
        this.props = props;
        this.clock = clock;
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

    public String generateRefreshToken(
            String subject,
            Duration ttl) {

        return generateToken(subject, List.of(), List.of(), ttl, true);
    }

    private String generateToken(
            String subject,
            List<String> roles,
            List<String> scopes,
            Duration ttl,
            boolean refresh) {

        try {
            Instant now = clock.now();

            Instant expiration = ttl != null
                    ? now.plus(ttl)
                    : now.plus(refresh ? props.refreshTtl() : props.accessTtl());

            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer(props.issuer())
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(expiration))
                    .jwtID(UUID.randomUUID().toString())
                    .claim(CLAIM_TOKEN_USE, refresh ? TOKEN_USE_REFRESH : TOKEN_USE_ACCESS);

            if (!refresh) {
                claims.claim(CLAIM_ROLES, sanitizeValues(roles));
                claims.claim(CLAIM_SCOPES, sanitizeValues(scopes));
            }

            JWSHeader header = new JWSHeader.Builder(resolveJwsAlgorithm())
                    .type(JOSEObjectType.JWT)
                    .keyID(keyProvider.activeKid())
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(resolveSigner());

            return jwt.serialize();

        } catch (Exception ex) {
            throw new IllegalStateException("JWT generation failed", ex);
        }
    }

    // ======================================================
    // CLAIM SANITIZATION (SEMANTIC ONLY)
    // ======================================================

    private List<String> sanitizeValues(List<String> values) {
        if (values == null || values.isEmpty()) {
            return List.of();
        }

        return values.stream()
                .filter(v -> v != null && !v.isBlank())
                .map(String::trim)
                .distinct()
                .toList();
    }

    // ======================================================
    // VALIDATION ENTRY POINT
    // ======================================================

    /**
     * Performs cryptographic and temporal validation only.
     *
     * @throws JwtValidationException if signature, structure or timing is invalid
     */
    public JWTClaimsSet validateAndParse(String token) {

        try {
            SignedJWT jwt = SignedJWT.parse(token);

            validateHeader(jwt);
            validateSignature(jwt);
            validateTemporalClaims(jwt.getJWTClaimsSet());

            return jwt.getJWTClaimsSet();

        } catch (Exception ex) {
            throw new JwtValidationException(ex);
        }
    }

    // ======================================================
    // INTERNAL VALIDATION STEPS
    // ======================================================

    private void validateHeader(SignedJWT jwt) throws JOSEException {

        if (!resolveJwsAlgorithm().equals(jwt.getHeader().getAlgorithm())) {
            throw new JOSEException("Invalid JWT alg");
        }

        if (!JOSEObjectType.JWT.equals(jwt.getHeader().getType())) {
            throw new JOSEException("Invalid JWT typ");
        }

        if (jwt.getHeader().getKeyID() == null || jwt.getHeader().getKeyID().isBlank()) {
            throw new JOSEException("Missing JWT kid");
        }
    }

    private void validateSignature(SignedJWT jwt) throws JOSEException {

        JWSVerifier verifier = resolveVerifier(jwt.getHeader().getKeyID());

        if (!jwt.verify(verifier)) {
            throw new JOSEException("Invalid JWT signature");
        }
    }

    private void validateTemporalClaims(JWTClaimsSet claims) throws JOSEException {

        Instant now = clock.now();
        long skew = props.allowedClockSkewSeconds();

        if (claims.getExpirationTime() == null ||
                claims.getExpirationTime().toInstant().isBefore(now.minusSeconds(skew))) {
            throw new JOSEException("JWT expired");
        }

        if (claims.getIssueTime() != null &&
                claims.getIssueTime().toInstant().isAfter(now.plusSeconds(skew))) {
            throw new JOSEException("Invalid iat");
        }

        if (claims.getNotBeforeTime() != null &&
                claims.getNotBeforeTime().toInstant().isAfter(now.plusSeconds(skew))) {
            throw new JOSEException("Invalid nbf");
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
            return new MACSigner(resolveHmacSecret());
        }

        return new RSASSASigner(keyProvider.privateKey());
    }

    private JWSVerifier resolveVerifier(String kid) throws JOSEException {

        if (props.algorithm() == JwtAlgorithm.HMAC) {
            return new MACVerifier(resolveHmacSecret());
        }

        RSAPublicKey publicKey = keyProvider.findPublicKey(kid)
                .orElseThrow(() -> new JOSEException("Unknown kid"));

        return new RSASSAVerifier(publicKey);
    }

    private byte[] resolveHmacSecret() {
        return Base64.getDecoder()
                .decode(props.hmac().secretBase64().getBytes(StandardCharsets.UTF_8));
    }

    // ======================================================
    // TECHNICAL HELPERS (NOT FOR AUTHZ)
    // ======================================================

    /**
     * Technical validity check only.
     * Never use for authorization decisions.
     */
    public boolean isValid(String token) {
        try {
            validateAndParse(token);
            return true;
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Extracts subject after cryptographic validation.
     */
    public String extractSubject(String token) {
        return validateAndParse(token).getSubject();
    }
}
