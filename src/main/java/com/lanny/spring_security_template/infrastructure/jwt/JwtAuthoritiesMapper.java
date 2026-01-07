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
 * <h2>Normalization rules</h2>
 * <ul>
 * <li>Roles are mapped as-is (expected to be {@code ROLE_*})</li>
 * <li>Scopes are prefixed with {@code SCOPE_}</li>
 * </ul>
 *
 * <p>
 * This strict mapping prevents privilege escalation and guarantees
 * deterministic authorization behavior across the system.
 * </p>
 */
@Component
public class JwtAuthoritiesMapper {

    /**
     * Converts validated JWT claims into Spring Security authorities.
     *
     * @param claims validated domain-level JWT claims
     * @return immutable collection of granted authorities
     * @throws NoAuthoritiesException if no authorities can be derived
     */
    public Collection<SimpleGrantedAuthority> map(JwtClaimsDTO claims) {

        Set<SimpleGrantedAuthority> authorities = new HashSet<>();

        claims.roles()
                .forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));

        claims.scopes()
                .forEach(scope -> authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope)));

        if (authorities.isEmpty()) {
            throw new NoAuthoritiesException();
        }

        return Set.copyOf(authorities);
    }
}
