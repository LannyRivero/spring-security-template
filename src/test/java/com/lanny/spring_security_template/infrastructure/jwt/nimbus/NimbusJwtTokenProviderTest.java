package com.lanny.spring_security_template.infrastructure.jwt.nimbus;

import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@DisplayName("🔐 NimbusJwtTokenProvider Tests")
class NimbusJwtTokenProviderTest {

    @Mock
    private JwtUtils jwtUtils;

    @InjectMocks
    private NimbusJwtTokenProvider provider;

    private final String fakeToken = "fake.jwt.token";

    @BeforeEach
    void verifyMocks() {
        assertNotNull(jwtUtils, "JwtUtils mock should be injected");
        assertNotNull(provider, "Provider should be instantiated");
    }

    // ------------------------------------------------------------
    // GROUP 1: Token Validation
    // ------------------------------------------------------------
    @Nested
    @DisplayName(" validateToken()")
    class ValidateTokenTests {

        @Test
        @DisplayName(" should return true when JwtUtils returns valid claims")
        void shouldValidateTokenSuccessfully() throws Exception {
            // Arrange
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("bob")
                    .issueTime(new java.util.Date())
                    .expirationTime(new java.util.Date(System.currentTimeMillis() + 60000))
                    .build();

            when(jwtUtils.validateAndParse(fakeToken)).thenReturn(claims);

            // Act
            boolean valid = provider.validateToken(fakeToken);

            // Assert
            assertTrue(valid, "Token should be valid when JwtUtils returns claims");
        }

        @Test
        @DisplayName(" should return false when JwtUtils throws an exception")
        void shouldReturnFalseWhenTokenInvalid() {
            when(jwtUtils.validateAndParse(fakeToken)).thenThrow(new RuntimeException("Invalid token"));

            boolean valid = provider.validateToken(fakeToken);

            assertFalse(valid, "Token should be invalid when JwtUtils throws exception");
        }
    }

    // ------------------------------------------------------------
    // GROUP 2: Subject Extraction
    // ------------------------------------------------------------
    @Nested
    @DisplayName(" extractSubject()")
    class ExtractSubjectTests {

        @Test
        @DisplayName(" should extract subject correctly from token claims")
        void shouldExtractSubjectSuccessfully() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder().subject("charlie").build();
            when(jwtUtils.validateAndParse(fakeToken)).thenReturn(claims);

            String subject = provider.extractSubject(fakeToken);

            assertEquals("charlie", subject, "Subject should match the one in claims");
        }
    }

    // ------------------------------------------------------------
    // GROUP 3: Claim Parsing
    // ------------------------------------------------------------
    @Nested
    @DisplayName(" parseClaims()")
    class ParseClaimsTests {

        @Test
        @DisplayName(" should parse claims and return TokenClaims correctly")
        void shouldParseClaimsSuccessfully() throws Exception {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("david")
                    .claim("roles", List.of("ROLE_USER"))
                    .claim("scopes", List.of("profile:read"))
                    .issueTime(new java.util.Date())
                    .expirationTime(new java.util.Date(System.currentTimeMillis() + 60000))
                    .jwtID("12345")
                    .issuer("issuer-example")
                    .audience(List.of("aud1"))
                    .build();

            when(jwtUtils.validateAndParse(fakeToken)).thenReturn(claims);

            var result = provider.parseClaims(fakeToken);

            assertTrue(result.isPresent(), "TokenClaims should be present");
            assertEquals("david", result.get().sub());
            assertEquals(List.of("ROLE_USER"), result.get().roles());
            assertEquals(List.of("profile:read"), result.get().scopes());
        }

        @Test
        @DisplayName(" should return empty Optional when JwtUtils throws exception")
        void shouldReturnEmptyOptionalWhenTokenInvalid() {
            when(jwtUtils.validateAndParse(fakeToken)).thenThrow(new RuntimeException("Invalid"));

            var result = provider.parseClaims(fakeToken);

            assertTrue(result.isEmpty(), "Should return empty Optional when token is invalid");
        }
    }

    // ------------------------------------------------------------
    // GROUP 4: Token Generation
    // ------------------------------------------------------------
    @Nested
    @DisplayName(" Token generation methods")
    class TokenGenerationTests {

        @Test
        @DisplayName(" should generate access and refresh tokens successfully")
        void shouldGenerateAccessAndRefreshTokens() {
            when(jwtUtils.generateAccessToken("alice", List.of("ROLE_USER"), List.of("profile:read"),
                    Duration.ofMinutes(5)))
                    .thenReturn("access.token");
            when(jwtUtils.generateRefreshToken("alice", Duration.ofDays(7)))
                    .thenReturn("refresh.token");

            String access = provider.generateAccessToken("alice", List.of("ROLE_USER"), List.of("profile:read"),
                    Duration.ofMinutes(5));
            String refresh = provider.generateRefreshToken("alice", Duration.ofDays(7));

            assertEquals("access.token", access, "Access token should match the expected value");
            assertEquals("refresh.token", refresh, "Refresh token should match the expected value");
        }
    }
}
