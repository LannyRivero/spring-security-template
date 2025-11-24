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
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/**
 * Utility for generating and validating JWTs (Access + Refresh) using RSA keys.
 */
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

    /** Generate access token (with roles & scopes) */
    public String generateAccessToken(String subject, List<String> roles, List<String> scopes) {
        return generateToken(subject, roles, scopes, null, false);
    }

    /** Generate refresh token */
    public String generateRefreshToken(String subject) {
        return generateToken(subject, List.of(), List.of(), null, true);
    }

    /**
     * Public overload allowing a custom TTL (used by TokenProvider)
     */
    public String generateToken(String subject, List<String> roles, List<String> scopes, Duration ttl,
            boolean isRefresh) {
        try {
            Instant now = clockProvider.now();
            Instant exp = (ttl != null)
                    ? now.plus(ttl)
                    : now.plus(isRefresh ? props.refreshTtl() : props.accessTtl());

            String audience = isRefresh
                    ? Optional.ofNullable(props.refreshAudience()).orElse(props.accessAudience())
                    : props.accessAudience();

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
                    .build();

            SignedJWT jwt = new SignedJWT(header, claims.build());
            jwt.sign(new RSASSASigner((RSAPrivateKey) keyProvider.privateKey()));
            return jwt.serialize();

        } catch (Exception e) {
            throw new IllegalStateException("Error creating JWT", e);
        }
    }

    /** Validate signature and expiration */
    public JWTClaimsSet validateAndParse(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            JWSVerifier verifier = new RSASSAVerifier((RSAPublicKey) keyProvider.publicKey());

            if (!jwt.verify(verifier)) {
                throw new JOSEException("Invalid signature");
            }

            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            Instant now = clockProvider.now();

            if (claims.getExpirationTime() == null || claims.getExpirationTime().toInstant().isBefore(now)) {
                throw new JOSEException("Token expired");
            }

            if (!Objects.equals(claims.getIssuer(), props.issuer())) {
                throw new JOSEException("Invalid issuer");
            }

            List<String> aud = claims.getAudience();
            String expectedAud = isRefreshClaim(claims)
                    ? Optional.ofNullable(props.refreshAudience()).orElse(props.accessAudience())
                    : props.accessAudience();

            if (aud != null && !aud.contains(expectedAud)) {
                throw new JOSEException("Invalid audience");
            }

            return claims;

        } catch (Exception e) {
            throw new RuntimeException("Invalid token: " + e.getMessage(), e);
        }
    }

    private boolean isRefreshClaim(JWTClaimsSet claims) {
        try {
            return "refresh".equals(claims.getStringClaim("type"));
        } catch (Exception e) {
            return false;
        }
    }

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
