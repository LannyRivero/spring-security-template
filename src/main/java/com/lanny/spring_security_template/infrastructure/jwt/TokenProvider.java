package com.lanny.spring_security_template.infrastructure.jwt;

import java.util.List;

public interface TokenProvider {
    String generateAccessToken(String subject, List<String> roles, List<String> scopes);

    String generateRefreshToken(String subject);

    boolean validateToken(String token);

    String extractSubject(String token);
}
