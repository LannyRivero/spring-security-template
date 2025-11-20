package com.lanny.spring_security_template.infrastructure.security.jwt;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.stereotype.Component;

import java.time.Instant;
import java.util.List;

@Component
public class StrictJwtValidator implements JwtValidator {

    private final SecurityJwtProperties props;

    public StrictJwtValidator(SecurityJwtProperties props) {
        this.props = props;
    }

    @Override
    public JwtClaimsDTO validate(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            var claimsSet = jwt.getJWTClaimsSet();

            String issuer = claimsSet.getIssuer();
            if (issuer == null || !issuer.equals(props.issuer())) {
                throw new IllegalArgumentException("Invalid token issuer");
            }

            List<String> aud = claimsSet.getAudience();
            if (aud == null || aud.isEmpty()) {
                throw new IllegalArgumentException("Missing audience");
            }

            Long iat = claimsSet.getIssueTime() != null
                    ? claimsSet.getIssueTime().toInstant().getEpochSecond()
                    : null;
            if (iat == null) {
                throw new IllegalArgumentException("Missing issue time");
            }

            Long nbf = claimsSet.getNotBeforeTime() != null
                    ? claimsSet.getNotBeforeTime().toInstant().getEpochSecond()
                    : 0L;

            Long exp = claimsSet.getExpirationTime() != null
                    ? claimsSet.getExpirationTime().toInstant().getEpochSecond()
                    : null;
            if (exp == null || Instant.now().getEpochSecond() >= exp) {
                throw new IllegalArgumentException("Token expired");
            }

            String jti = claimsSet.getJWTID();
            if (jti == null || jti.isBlank()) {
                throw new IllegalArgumentException("Missing jti");
            }

            String sub = claimsSet.getSubject();
            if (sub == null || sub.isBlank()) {
                throw new IllegalArgumentException("Missing subject");
            }

            // EXTRAER ROLES Y SCOPES
            List<String> roles = claimsSet.getStringListClaim("roles");
            if (roles == null)
                roles = List.of();

            List<String> scopes = claimsSet.getStringListClaim("scopes");
            if (scopes == null)
                scopes = List.of();

            return new JwtClaimsDTO(
                    sub,
                    jti,
                    aud,
                    iat,
                    nbf,
                    exp,
                    roles,
                    scopes);

        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid JWT: " + e.getMessage());
        }
    }
}