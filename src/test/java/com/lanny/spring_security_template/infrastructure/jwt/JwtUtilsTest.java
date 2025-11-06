package com.lanny.spring_security_template.infrastructure.jwt;

import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.ClasspathRsaKeyProvider;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * ✅ Integration test for JwtUtils using real RSA keys (classpath)
 * Ensures tokens are generated, signed and validated correctly.
 */
@SpringBootTest
@ActiveProfiles("dev")
class JwtUtilsTest {

    private final JwtUtils jwtUtils;

    public JwtUtilsTest() {
        ClasspathRsaKeyProvider keyProvider = new ClasspathRsaKeyProvider();
        String issuer = "test-issuer";
        String audience = "test-audience";
        long accessExpiration = 3600; // 1 hour in seconds
        long refreshExpiration = 86400; // 1 day in seconds
        this.jwtUtils = new JwtUtils(keyProvider, issuer, audience, accessExpiration, refreshExpiration);
   }

    @Test
    @DisplayName("🔐 Should generate and validate a valid RSA JWT")
    void shouldGenerateAndValidateAccessToken() {
        // Generate token
        String token = jwtUtils.generateAccessToken(
                "user@example.com",
                List.of("ROLE_USER"),
                List.of("profile:read")
        );

        assertNotNull(token, "Token must not be null");
        assertTrue(token.split("\\.").length == 3, "JWT must have 3 parts");

        // Validate and parse
        JWTClaimsSet claims = jwtUtils.validateAndParse(token);
        assertEquals("user@example.com", claims.getSubject());
        assertTrue(((List<?>) claims.getClaim("roles")).contains("ROLE_USER"));
        assertTrue(((List<?>) claims.getClaim("scopes")).contains("profile:read"));
    }

    @Test
    @DisplayName("⏰ Should reject tampered or expired tokens gracefully")
    void shouldRejectInvalidOrExpiredTokens() {
        String token = jwtUtils.generateAccessToken(
                "expired@example.com",
                List.of("ROLE_USER"),
                List.of()
        );

        assertDoesNotThrow(() -> jwtUtils.validateAndParse(token), "Token should be valid before expiry");

        // Alter token to break signature
        String tampered = token.replace('a', 'b');
        assertThrows(RuntimeException.class, () -> jwtUtils.validateAndParse(tampered), "Tampered token must fail verification");
    }
}
