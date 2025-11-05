package com.lanny.spring_security_template.application.auth.port.out;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

public interface TokenProvider {

    String generateAccessToken(String subject, List<String> roles, List<String> scopes, Duration ttl);

    String generateRefreshToken(String subject, Duration ttl);

    boolean validateToken(String token);

    String extractSubject(String token);

    Optional<TokenClaims> parseClaims(String token);

    record TokenClaims(
            String sub,
            List<String> roles,
            List<String> scopes,
            long iat,
            long exp,
            String jti,
            String iss,
            List<String> aud) {
    }
}
