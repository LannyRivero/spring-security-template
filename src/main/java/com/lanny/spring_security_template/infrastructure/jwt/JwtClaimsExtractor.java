package com.lanny.spring_security_template.infrastructure.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 *  JwtClaimsExtractor
 * 
 * Extrae y normaliza roles y scopes desde los claims del JWT.
 * Garantiza que:
 *   - Los roles comiencen con "ROLE_"
 *   - Los scopes comiencen con "SCOPE_"
 *   - Soporta tanto listas como valores únicos tipo String.
 */
@Component
public class JwtClaimsExtractor {

    public List<String> extractRoles(JWTClaimsSet claims) {
        Object roles = claims.getClaim("roles");
        List<String> result = List.of();

        if (roles instanceof List<?> list) {
            result = list.stream().map(Object::toString).toList();
        } else if (roles instanceof String s) {
            result = List.of(s);
        }

        // Normalizar prefijos
        return result.stream()
                .map(r -> r.startsWith("ROLE_") ? r : "ROLE_" + r)
                .toList();
    }

    public List<String> extractScopes(JWTClaimsSet claims) {
        Object scopes = claims.getClaim("scopes");
        List<String> result = List.of();

        if (scopes instanceof List<?> list) {
            result = list.stream().map(Object::toString).toList();
        } else if (scopes instanceof String s) {
            result = List.of(s);
        }

        // Normalizar prefijos
        return result.stream()
                .map(s -> s.startsWith("SCOPE_") ? s : "SCOPE_" + s)
                .toList();
    }
}
