package com.lanny.spring_security_template.infrastructure.jwt;

import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.stereotype.Component;
import java.util.*;

@Component
public class JwtClaimsExtractor {

    public List<String> extractRoles(JWTClaimsSet claims) {
        Object roles = claims.getClaim("roles");
        if (roles instanceof List<?> list)
            return list.stream().map(Object::toString).toList();
        if (roles instanceof String s)
            return List.of(s); 
        return List.of();
    }

    public List<String> extractScopes(JWTClaimsSet claims) {
        Object scopes = claims.getClaim("scopes");
        if (scopes instanceof List<?> list)
            return list.stream().map(Object::toString).toList();
        return List.of();
    }
}
