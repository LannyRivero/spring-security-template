package com.lanny.spring_security_template.infrastructure.security.jwt;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.InvalidJwtAudienceException;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.InvalidJwtIssuerException;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.MissingJwtClaimException;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * {@code StrictJwtValidator}
 *
 * <p>
 * High-level JWT validator enforcing <b>semantic and domain-specific security
 * rules</b>
 * on top of low-level cryptographic validation.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Delegate <b>all cryptographic and temporal validation</b>
 * (signature, alg, kid, exp, iat, nbf)
 * to {@link JwtUtils}</li>
 * <li>Enforce <b>issuer, audience and token_use semantics</b></li>
 * <li>Validate presence of mandatory claims</li>
 * <li>Produce a {@link JwtClaimsDTO} for the security layer</li>
 * </ul>
 *
 * <h2>Explicitly NOT responsible for</h2>
 * <ul>
 * <li>Signature verification</li>
 * <li>Time-based validation</li>
 * <li>Authorization decisions</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Only tokens issued by the configured issuer are accepted</li>
 * <li>Audience is validated according to {@code token_use}</li>
 * <li>Malformed or forged claims are rejected deterministically</li>
 * </ul>
 *
 * <p>
 * This design follows OWASP ASVS and is suitable for banking-grade systems.
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

        // --------------------------------------------------
        // 4. token_use semantics
        // --------------------------------------------------
        TokenUse tokenUse = TokenUse.from(
                (String) claims.getClaim(CLAIM_TOKEN_USE));

        // --------------------------------------------------
        // 5. Audience validation (depends on token_use)
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
        // 6. Controlled extraction
        // --------------------------------------------------
        List<String> roles = safeStringList(claims, CLAIM_ROLES);
        List<String> scopes = safeStringList(claims, CLAIM_SCOPES);

        return new JwtClaimsDTO(
                subject,
                jti,
                audience,
                claims.getIssueTime().toInstant().getEpochSecond(),
                claims.getNotBeforeTime() != null
                        ? claims.getNotBeforeTime().toInstant().getEpochSecond()
                        : 0L,
                claims.getExpirationTime().toInstant().getEpochSecond(),
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
