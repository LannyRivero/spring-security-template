package com.lanny.spring_security_template.infrastructure.jwt;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.infrastructure.security.jwt.exception.NoAuthoritiesException;

/**
 * {@code JwtAuthoritiesMapper}
 *
 * <p>
 * Maps validated JWT domain claims into Spring Security authorities.
 * </p>
 *
 * <p>
 * This component operates exclusively on {@link JwtClaimsDTO},
 * ensuring that only cryptographically valid and domain-validated
 * tokens can produce granted authorities.
 * </p>
 *
 * <h2>Authority contract</h2>
 * <ul>
 * <li>Roles are normalized to {@code ROLE_*}</li>
 * <li>Scopes are normalized to {@code SCOPE_*}</li>
 * <li>Invalid or blank entries are ignored</li>
 * </ul>
 *
 * <p>
 * This explicit normalization prevents authorization mismatches
 * and guarantees deterministic behavior across environments.
 * </p>
 */
@Component
public class JwtAuthoritiesMapper {

    private static final String ROLE_PREFIX = "ROLE_";
    private static final String SCOPE_PREFIX = "SCOPE_";

    /**
     * Converts validated JWT claims into Spring Security authorities.
     *
     * @param claims validated domain-level JWT claims
     * @return immutable collection of granted authorities
     * @throws NoAuthoritiesException if no authorities can be derived
     */
    public Collection<SimpleGrantedAuthority> map(JwtClaimsDTO claims) {

        Set<SimpleGrantedAuthority> authorities = new HashSet<>();

        claims.roles().stream()
                .map(String::trim)
                .filter(role -> !role.isBlank())
                .map(this::normalizeRole)
                .forEach(authority -> authorities.add(new SimpleGrantedAuthority(authority)));

        claims.scopes().stream()
                .map(String::trim)
                .filter(scope -> !scope.isBlank())
                .forEach(scope -> authorities.add(new SimpleGrantedAuthority(SCOPE_PREFIX + scope)));

        if (authorities.isEmpty()) {
            throw new NoAuthoritiesException();
        }

        return Set.copyOf(authorities);
    }

    private String normalizeRole(String role) {
        return role.startsWith(ROLE_PREFIX)
                ? role
                : ROLE_PREFIX + role;
    }
}
