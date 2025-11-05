package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;

@Component
@ConditionalOnProperty(name = "security.jwt.provider", havingValue = "nimbus")
public class NimbusJwtTokenProvider implements TokenProvider {

    private final JwtUtils jwtUtils;

    public NimbusJwtTokenProvider(JwtUtils jwtUtils) {
        this.jwtUtils = jwtUtils;
    }

    @Override
    public String generateAccessToken(String subject, List<String> roles, List<String> scopes) {
        return jwtUtils.generateAccessToken(subject, roles, scopes);
    }

    @Override
    public String generateRefreshToken(String subject) {
        return jwtUtils.generateRefreshToken(subject);
    }

    @Override
    public boolean validateToken(String token) {
        try {
            jwtUtils.validateAndParse(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public String extractSubject(String token) {
        return jwtUtils.validateAndParse(token).getSubject();
    }
}
