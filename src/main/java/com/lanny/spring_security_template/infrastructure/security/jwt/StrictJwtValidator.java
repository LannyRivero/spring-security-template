package com.lanny.spring_security_template.infrastructure.security.jwt;

import java.util.List;

import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.InvalidJwtAudienceException;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.InvalidJwtIssuerException;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.MissingJwtClaimException;
import com.nimbusds.jwt.JWTClaimsSet;

/**
 * {@code StrictJwtValidator}
 *
 * High-level JWT validator enforcing semantic and domain-specific rules
 * on top of cryptographic validation.
 *
 * <p>
 * ACCESS and REFRESH tokens are validated with different semantics.
 * </p>
 */
@Component
public class StrictJwtValidator implements JwtValidator {

    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_SCOPES = "scopes";
    private static final String CLAIM_TOKEN_USE = "token_use";

    private final JwtUtils jwtUtils;
    private final SecurityJwtProperties props;

    public StrictJwtValidator(
            JwtUtils jwtUtils,
            SecurityJwtProperties props) {
        this.jwtUtils = jwtUtils;
        this.props = props;
    }

    @Override
    public JwtClaimsDTO validate(String token) {

        // --------------------------------------------------
        // 1. Cryptographic + temporal validation
        // --------------------------------------------------
        JWTClaimsSet claims = jwtUtils.validateAndParse(token);

        // --------------------------------------------------
        // 2. Issuer validation
        // --------------------------------------------------
        if (!props.issuer().equals(claims.getIssuer())) {
            throw new InvalidJwtIssuerException();
        }

        // --------------------------------------------------
        // 3. Mandatory claims
        // --------------------------------------------------
        String subject = claims.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new MissingJwtClaimException("sub");
        }

        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) {
            throw new MissingJwtClaimException("jti");
        }

        Object rawTokenUse = claims.getClaim(CLAIM_TOKEN_USE);
        if (!(rawTokenUse instanceof String)) {
            throw new MissingJwtClaimException(CLAIM_TOKEN_USE);
        }

        TokenUse tokenUse = TokenUse.from((String) rawTokenUse);

        // --------------------------------------------------
        // 4. Audience validation (depends on token_use)
        // --------------------------------------------------
        List<String> audience = claims.getAudience();
        if (audience == null || audience.isEmpty()) {
            throw new MissingJwtClaimException("aud");
        }

        String expectedAudience = switch (tokenUse) {
            case ACCESS -> props.accessAudience();
            case REFRESH -> props.refreshAudience();
        };

        if (!audience.contains(expectedAudience)) {
            throw new InvalidJwtAudienceException();
        }

        // --------------------------------------------------
        // 5. Controlled extraction
        // --------------------------------------------------
        // Roles and scopes are ONLY expected for ACCESS tokens.
        // REFRESH tokens must not carry authorization data.
        List<String> roles = safeStringList(claims, CLAIM_ROLES);
        List<String> scopes = safeStringList(claims, CLAIM_SCOPES);

        long issuedAt = claims.getIssueTime() != null
                ? claims.getIssueTime().toInstant().getEpochSecond()
                : 0L;

        long notBefore = claims.getNotBeforeTime() != null
                ? claims.getNotBeforeTime().toInstant().getEpochSecond()
                : 0L;

        long expiresAt = claims.getExpirationTime() != null
                ? claims.getExpirationTime().toInstant().getEpochSecond()
                : 0L;

        return new JwtClaimsDTO(
                subject,
                jti,
                audience,
                issuedAt,
                notBefore,
                expiresAt,
                roles,
                scopes,
                tokenUse.name().toLowerCase());
    }

    // ======================================================
    // Helpers
    // ======================================================

    /**
     * Safely extracts a list claim as an immutable list.
     *
     * <p>
     * Any malformed or unexpected claim value results in an empty list,
     * never an exception.
     * </p>
     */
    private List<String> safeStringList(JWTClaimsSet claims, String name) {
        try {
            List<String> values = claims.getStringListClaim(name);
            return values != null ? List.copyOf(values) : List.of();
        } catch (Exception ex) {
            return List.of();
        }
    }
}
