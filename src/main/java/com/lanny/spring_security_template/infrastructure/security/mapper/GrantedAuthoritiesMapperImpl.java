package com.lanny.spring_security_template.infrastructure.security.mapper;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.stereotype.Component;

/**
 * GrantedAuthoritiesMapperImpl
 *
 * Normaliza las autoridades (roles y scopes) para mantener un formato
 * coherente:
 * - "USER" → "ROLE_USER"
 * - "profile:read" → "SCOPE_profile:read"
 * - Ya normalizadas ("ROLE_ADMIN" o "SCOPE_x") se mantienen igual.
 */
@Component
public class GrantedAuthoritiesMapperImpl implements GrantedAuthoritiesMapper {

    private static final Logger log = LoggerFactory.getLogger(GrantedAuthoritiesMapperImpl.class);

    @Override
    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        if (authorities == null || authorities.isEmpty()) {
            return Set.of();
        }

        var normalized = authorities.stream()
                .map(a -> normalize(a.getAuthority()))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toUnmodifiableSet());

        log.debug(" Mapped authorities: {}", normalized);
        return normalized;
    }

    /**
     * Normaliza cada authority para cumplir el estándar ROLE_/SCOPE_.
     */
    private String normalize(String raw) {
        if (raw == null || raw.isBlank())
            return raw;
        var a = raw.trim();

        if (a.startsWith("ROLE_") || a.startsWith("SCOPE_"))
            return a;

        // Ej.: "profile:read" → "SCOPE_profile:read"
        if (a.contains(":"))
            return "SCOPE_" + a;

        // Ej.: "USER" → "ROLE_USER"
        return "ROLE_" + a;
    }
}
