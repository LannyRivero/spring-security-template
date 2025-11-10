package com.lanny.spring_security_template.config;

import com.lanny.spring_security_template.application.auth.port.out.TokenProvider;

import java.time.Duration;
import java.util.List;
import java.util.Optional;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;

@TestConfiguration
public class TestSecurityConfig {

    @Bean
    public TokenProvider tokenProvider() {
        // dummy implementation (no-op) for test context
        return new TokenProvider() {
            @Override
            public String generateAccessToken(String subject, List<String> roles, List<String> scopes, Duration ttl) {
                return "fake-access";
            }

            @Override
            public String generateRefreshToken(String subject, Duration ttl) {
                return "fake-refresh";
            }

            @Override
            public boolean validateToken(String token) {
                return true;
            }

            @Override
            public String extractSubject(String token) {
                return "test-user";
            }

            @Override
            public Optional<TokenClaims> parseClaims(String token) {
                return Optional.empty();
            }
        };
    }
}

