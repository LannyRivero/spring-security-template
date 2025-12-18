package com.lanny.spring_security_template.infrastructure.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Extracts and normalizes security authorities from JWT claims.
 *
 * <p>
 * This component is responsible for reading role and scope claims
 * from a {@link JWTClaimsSet} and converting them into Spring Security–
 * compatible authorities.
 * </p>
 *
 * <p>
 * Normalization rules:
 * </p>
 * <ul>
 * <li>Roles are prefixed with {@code ROLE_}</li>
 * <li>Scopes are prefixed with {@code SCOPE_}</li>
 * </ul>
 *
 * <p>
 * Supported claim formats:
 * </p>
 * <ul>
 * <li>{@code List<String>}</li>
 * <li>{@code String} (single value)</li>
 * </ul>
 *
 * <p>
 * If a claim is present but has an unsupported type, an
 * {@link IllegalArgumentException} is thrown. This is considered a
 * misconfiguration or token integrity issue.
 * </p>
 *
 * <p>
 * This class is intentionally strict to prevent malformed or
 * ambiguous authorities from entering the security context.
 * </p>
 */
@Component
public class JwtClaimsExtractor {

    /**
     * Extracts role authorities from the {@code roles} JWT claim.
     */
    public List<String> extractRoles(JWTClaimsSet claims) {
        return extract(claims.getClaim("roles"), "ROLE_");
    }

    /**
     * Extracts scope authorities from the {@code scopes} JWT claim.
     */
    public List<String> extractScopes(JWTClaimsSet claims) {
        return extract(claims.getClaim("scopes"), "SCOPE_");
    }

    private List<String> extract(Object claim, String prefix) {
        List<String> values;

        if (claim == null) {
            return List.of();
        }

        if (claim instanceof List<?> list) {
            values = list.stream()
                    .filter(v -> v != null)
                    .map(Object::toString)
                    .toList();
        } else if (claim instanceof String s) {
            values = List.of(s);
        } else {
            throw new IllegalArgumentException(
                    "Invalid claim type for authorities: " + claim.getClass());
        }

        return values.stream()
                .filter(v -> !v.isBlank())
                .map(v -> v.startsWith(prefix) ? v : prefix + v)
                .toList();
    }
}
