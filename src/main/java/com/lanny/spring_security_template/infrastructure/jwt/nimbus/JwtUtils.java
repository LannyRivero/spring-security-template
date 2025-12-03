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

@Component
public class JwtUtils {

    private final RsaKeyProvider keyProvider;
    private final SecurityJwtProperties props;
    private final ClockProvider clockProvider;

    public JwtUtils(RsaKeyProvider keyProvider,
            SecurityJwtProperties props,
            ClockProvider clockProvider) {
        this.keyProvider = keyProvider;
        this.props = props;
        this.clockProvider = clockProvider;
    }

    // ======================================================
    // GENERACIÓN DE TOKENS
    // ======================================================

    public String generateAccessToken(String subject, List<String> roles, List<String> scopes) {
        return generateToken(subject, roles, scopes, null, false);
    }

    public String generateRefreshToken(String subject) {
        return generateToken(subject, List.of(), List.of(), null, true);
    }

    public String generateToken(String subject,
            List<String> roles,
            List<String> scopes,
            Duration ttl,
            boolean isRefresh) {
        try {
            Instant now = clockProvider.now();
            Instant exp = (ttl != null)
                    ? now.plus(ttl)
                    : now.plus(isRefresh ? props.refreshTtl() : props.accessTtl());

            // audience correcta
            String audience = isRefresh
                    ? Optional.ofNullable(props.refreshAudience()).orElse(props.accessAudience())
                    : props.accessAudience();

            // Claims
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .subject(subject)
                    .issuer(props.issuer())
                    .audience(audience)
                    .issueTime(Date.from(now))
                    .expirationTime(Date.from(exp))
                    .jwtID(UUID.randomUUID().toString());

            if (isRefresh) {
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
            throw new IllegalStateException("Error generating JWT: " + e.getMessage(), e);
        }
    }

    // ======================================================
    // VALIDACIÓN COMPLETA
    // ======================================================

    public JWTClaimsSet validateAndParse(String token) {
        try {
            // 1. Parseo
            SignedJWT jwt = SignedJWT.parse(token);

            // 2. Validar header
            validateHeader(jwt);

            // 3. Validar firma
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) keyProvider.publicKey());
            if (!jwt.verify(verifier)) {
                throw new JOSEException("Invalid signature");
            }

            // 4. Claims
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            validateClaims(claims);

            return claims;

        } catch (java.text.ParseException e) {
            throw new RuntimeException("Malformed JWT: " + e.getMessage(), e);

        } catch (Exception e) {
            throw new RuntimeException("Invalid token: " + e.getMessage(), e);
        }
    }

    // ======================================================
    // HEADER VALIDATION
    // ======================================================
    private void validateHeader(SignedJWT jwt) throws JOSEException {

        // Algoritmo correcto
        if (!JWSAlgorithm.RS256.equals(jwt.getHeader().getAlgorithm())) {
            throw new JOSEException("Invalid alg");
        }

        // Tipo correcto
        if (!JOSEObjectType.JWT.equals(jwt.getHeader().getType())) {
            throw new JOSEException("Invalid typ");
        }

        // Validar KID
        String kid = jwt.getHeader().getKeyID();
        if (kid != null && !kid.equals(keyProvider.keyId())) {
            throw new JOSEException("Unknown kid");
        }
    }

    // ======================================================
    // CLAIM VALIDATION
    // ======================================================

    private void validateClaims(JWTClaimsSet claims) throws JOSEException {
        Instant now = clockProvider.now();

        // Expiration
        if (claims.getExpirationTime() == null ||
                claims.getExpirationTime().toInstant().isBefore(now)) {
            throw new JOSEException("Token expired");
        }

        // nbf (optional)
        if (claims.getNotBeforeTime() != null &&
                claims.getNotBeforeTime().toInstant().isAfter(now)) {
            throw new JOSEException("Token not valid yet");
        }

        // Issuer
        if (!Objects.equals(claims.getIssuer(), props.issuer())) {
            throw new JOSEException("Invalid issuer");
        }

        // Audience correcta según tipo
        String expectedAud = isRefreshClaim(claims)
                ? Optional.ofNullable(props.refreshAudience()).orElse(props.accessAudience())
                : props.accessAudience();

        List<String> aud = claims.getAudience();
        if (aud == null || !aud.contains(expectedAud)) {
            throw new JOSEException("Invalid audience");
        }

        // Validar coherencia refresh/access
        validateTokenType(claims);
    }

    @SuppressWarnings("unchecked")
    private void validateTokenType(JWTClaimsSet claims) throws JOSEException {
        boolean refresh = isRefreshClaim(claims);

        if (refresh) {
            List<String> roles = (List<String>) claims.getClaim("roles");
            List<String> scopes = (List<String>) claims.getClaim("scopes");

            if (roles != null) {
                throw new JOSEException("Refresh token must not contain roles");
            }
            if (scopes != null) {
                throw new JOSEException("Refresh token must not contain scopes");
            }
        }
    }

    private boolean isRefreshClaim(JWTClaimsSet claims) {
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
