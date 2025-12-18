package com.lanny.spring_security_template.application.auth.port.out.dto;

import java.util.List;

public record JwtClaimsDTO(
        String sub,
        String jti,
        List<String> aud,
        long iat,
        long nbf,
        long exp,
        List<String> roles,
        List<String> scopes,
        String tokenUse
) {
        public boolean isAccessToken() {
        return "access".equalsIgnoreCase(tokenUse);
    }

    public boolean isRefreshToken() {
        return "refresh".equalsIgnoreCase(tokenUse);
    }
}

