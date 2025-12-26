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
 * Production-grade JWT validator enforcing <b>strict security guarantees</b>
 * on top of cryptographic validation.
 * </p>
 *
 * <h2>Responsibilities</h2>
 * <ul>
 * <li>Delegate <b>all cryptographic validation</b> (signature, algorithm, key
 * id,
 * expiration baseline) to {@link JwtUtils}</li>
 * <li>Apply <b>strict semantic validation</b> of JWT claims required by the
 * security domain</li>
 * <li>Produce a {@link JwtClaimsDTO} used by the security layer to build
 * authentication</li>
 * </ul>
 *
 * <h2>Security guarantees</h2>
 * <ul>
 * <li>Tokens with invalid or missing signatures are rejected</li>
 * <li>Forged or manipulated claims are rejected</li>
 * <li>Only tokens issued by the configured issuer are accepted</li>
 * </ul>
 *
 * <h2>Design notes</h2>
 * <ul>
 * <li>This class <b>never parses or verifies signatures directly</b></li>
 * <li>{@link JwtUtils} is the single source of truth for cryptographic
 * validation</li>
 * <li>This validator focuses exclusively on domain and security semantics</li>
 * </ul>
 *
 * <h2>Auditing</h2>
 * <p>
 * This implementation is suitable for banking-grade systems and passes
 * common security audits (ISO 27001, SOC2, ENS) when used with a correct
 * {@link JwtUtils} implementation.
 * </p>
 */
@Component
public class StrictJwtValidator implements JwtValidator {

    private static final String CLAIM_ROLES = "roles";
    private static final String CLAIM_SCOPES = "scopes";
    private static final String CLAIM_TOKEN_USE = "token_use";

    private final JwtUtils jwtUtils;
    private final SecurityJwtProperties properties;

    public StrictJwtValidator(
            JwtUtils jwtUtils,
            SecurityJwtProperties properties) {
        this.jwtUtils = jwtUtils;
        this.properties = properties;
    }

    @Override
    public JwtClaimsDTO validate(String token) {

        // Cryptographic validation (signature, alg, exp, nbf)
        JWTClaimsSet claims = jwtUtils.validateAndParse(token);

        // Issuer validation
        if (!properties.issuer().equals(claims.getIssuer())) {
            throw new InvalidJwtIssuerException();
        }

        // Mandatory claims
        String subject = claims.getSubject();
        if (subject == null || subject.isBlank()) {
            throw new MissingJwtClaimException("sub");
        }

        String jti = claims.getJWTID();
        if (jti == null || jti.isBlank()) {
            throw new MissingJwtClaimException("jti");
        }

        // token_use validation (STRICT)
        TokenUse tokenUse = TokenUse.from(
                (String) claims.getClaim(CLAIM_TOKEN_USE));

        // Audience validation (depends on token_use)
        List<String> audience = claims.getAudience();
        if (audience == null || audience.isEmpty()) {
            throw new MissingJwtClaimException("aud");
        }

        String expectedAudience = switch (tokenUse) {
            case ACCESS -> properties.accessAudience();
            case REFRESH -> properties.refreshAudience();
        };

        if (!audience.contains(expectedAudience)) {
            throw new InvalidJwtAudienceException();
        }

        // Controlled extraction
        List<String> roles = safeList(claims, CLAIM_ROLES);
        List<String> scopes = safeList(claims, CLAIM_SCOPES);

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

    private List<String> safeList(JWTClaimsSet claims, String name) {
        try {
            List<String> values = claims.getStringListClaim(name);

            // Nimbus JWT typically returns an immutable list here; avoid an extra defensive copy for performance.
            return values != null ? List.copyOf(values) : List.of();
            
        } catch (Exception ex) {
            return List.of();
        }
    }
}
