package com.lanny.spring_security_template.infrastructure.jwt;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.key.classpath.ClasspathRsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;
import com.lanny.spring_security_template.infrastructure.time.SystemClockProvider;
import com.lanny.spring_security_template.domain.time.ClockProvider;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class JwtUtilsTest {

    private final JwtUtils jwtUtils;

    public JwtUtilsTest() {

        ClasspathRsaKeyProvider keyProvider = new ClasspathRsaKeyProvider(
                "keys/private_key.pem",
                "keys/public_key.pem");

        SecurityJwtProperties props = new SecurityJwtProperties(
                "test-issuer",
                "test-access-audience",
                "test-refresh-audience",
                Duration.ofHours(1),
                Duration.ofDays(1));

        ClockProvider clockProvider = new SystemClockProvider();

        this.jwtUtils = new JwtUtils(keyProvider, props, clockProvider);
    }

    @Test
    @DisplayName("🔐 Should generate and validate a valid RSA JWT")
    void shouldGenerateAndValidateAccessToken() {

        String token = jwtUtils.generateAccessToken(
                "user@example.com",
                List.of("ROLE_USER"),
                List.of("profile:read"),
                Duration.ofHours(1));

        assertNotNull(token);
        assertEquals(3, token.split("\\.").length);

        JWTClaimsSet claims = jwtUtils.validateAndParse(token);

        assertEquals("user@example.com", claims.getSubject());
        assertTrue(((List<?>) claims.getClaim("roles")).contains("ROLE_USER"));
        assertTrue(((List<?>) claims.getClaim("scopes")).contains("profile:read"));
    }

    @Test
    @DisplayName("⏰ Should reject tampered or expired tokens")
    void shouldRejectInvalidOrExpiredTokens() {

        String token = jwtUtils.generateAccessToken(
                "expired@example.com",
                List.of("ROLE_USER"),
                List.of(),
                Duration.ofHours(1));

        assertDoesNotThrow(() -> jwtUtils.validateAndParse(token));

        String tampered = token.replace('a', 'b');

        assertThrows(RuntimeException.class,
                () -> jwtUtils.validateAndParse(tampered));
    }
}
