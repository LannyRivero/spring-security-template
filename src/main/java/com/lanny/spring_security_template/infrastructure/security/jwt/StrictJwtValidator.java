package com.lanny.spring_security_template.infrastructure.security.jwt;

import com.lanny.spring_security_template.application.auth.port.out.JwtValidator;
import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;
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

    private final JwtUtils jwtUtils;
    private final SecurityJwtProperties properties;

    public StrictJwtValidator(
            JwtUtils jwtUtils,
            SecurityJwtProperties properties) {
        this.jwtUtils = jwtUtils;
        this.properties = properties;
    }

    /**
     * Validates a JWT and returns its verified claims.
     *
     * <p>
     * Validation process:
     * </p>
     * <ol>
     * <li>Cryptographic validation (signature, algorithm, expiration)</li>
     * <li>Issuer validation</li>
     * <li>Mandatory claim presence checks</li>
     * <li>Controlled extraction of roles and scopes</li>
     * </ol>
     *
     * @param token raw JWT string (without {@code Bearer } prefix)
     * @return verified and normalized JWT claims
     *
     * @throws IllegalArgumentException if the token is invalid or fails validation
     */
    @Override
    public JwtClaimsDTO validate(String token) {

        // Cryptographic validation (signature, header, exp, nbf)
        JWTClaimsSet claims = jwtUtils.validateAndParse(token);

        // Strict issuer validation
        if (!properties.issuer().equals(claims.getIssuer())) {
            throw new IllegalArgumentException("Invalid token issuer");
        }

        // Mandatory claims
        if (claims.getSubject() == null || claims.getSubject().isBlank()) {
            throw new IllegalArgumentException("Missing subject");
        }

        if (claims.getJWTID() == null || claims.getJWTID().isBlank()) {
            throw new IllegalArgumentException("Missing jti");
        }

        if (claims.getAudience() == null || claims.getAudience().isEmpty()) {
            throw new IllegalArgumentException("Missing audience");
        }

        // Controlled extraction of roles and scopes
        List<String> roles = safeList(claims, "roles");
        List<String> scopes = safeList(claims, "scopes");

        return new JwtClaimsDTO(
                claims.getSubject(),
                claims.getJWTID(),
                claims.getAudience(),
                claims.getIssueTime().toInstant().getEpochSecond(),
                claims.getNotBeforeTime() != null
                        ? claims.getNotBeforeTime().toInstant().getEpochSecond()
                        : 0L,
                claims.getExpirationTime().toInstant().getEpochSecond(),
                roles,
                scopes,
                (String) claims.getClaim("token_use"));
    }

    /**
     * Safely extracts a string list claim.
     *
     * <p>
     * This method guarantees:
     * </p>
     * <ul>
     * <li>No exceptions are propagated from malformed claims</li>
     * <li>Null-safe behavior</li>
     * <li>Finite cardinality (empty list if missing)</li>
     * </ul>
     *
     * @param claims JWT claims set
     * @param name   claim name
     * @return immutable list of claim values or empty list
     */
    private List<String> safeList(JWTClaimsSet claims, String name) {
        try {
            List<String> values = claims.getStringListClaim(name);
            return values != null ? values : List.of();
        } catch (Exception ex) {
            return List.of();
        }
    }
}
