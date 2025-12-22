package com.lanny.spring_security_template.infrastructure.security.jwt;

import com.lanny.spring_security_template.application.auth.port.out.dto.JwtClaimsDTO;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.JwtUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class StrictJwtValidatorTest {

    @Mock
    private JwtUtils jwtUtils;

    @Mock
    private SecurityJwtProperties props;

    private StrictJwtValidator validator;

    @BeforeEach
    void setUp() {
        validator = new StrictJwtValidator(jwtUtils, props);
    }

    private static JWTClaimsSet baseClaims(
            String issuer,
            String sub,
            String jti,
            List<String> aud) {
        Instant now = Instant.parse("2025-01-01T10:00:00Z");
        return new JWTClaimsSet.Builder()
                .issuer(issuer)
                .subject(sub)
                .jwtID(jti)
                .audience(aud)
                .issueTime(Date.from(now))
                .notBeforeTime(Date.from(now.minusSeconds(10)))
                .expirationTime(Date.from(now.plusSeconds(3600)))
                .build();
    }

    @Nested
    class HappyPath {

        @Test
        @DisplayName("validate() returns JwtClaimsDTO when token is cryptographically valid and claims are valid")
        void testShouldValidate_ok() {
            when(props.issuer()).thenReturn("issuer-A");

            JWTClaimsSet claims = baseClaims("issuer-A", "lanny", "jti-123", List.of("access"));
            claims = new JWTClaimsSet.Builder(claims)
                    .claim("roles", List.of("ROLE_USER"))
                    .claim("scopes", List.of("profile:read"))
                    .claim("token_use", "access")
                    .build();

            when(jwtUtils.validateAndParse("token")).thenReturn(claims);

            JwtClaimsDTO dto = validator.validate("token");

            assertEquals("lanny", dto.sub());
            assertEquals("jti-123", dto.jti());
            assertEquals(List.of("access"), dto.aud());
            assertEquals(List.of("ROLE_USER"), dto.roles());
            assertEquals(List.of("profile:read"), dto.scopes());
            assertEquals("access", dto.tokenUse());

            verify(jwtUtils, times(1)).validateAndParse("token");
        }

        @Test
        @DisplayName("validate() returns empty roles/scopes when claims are missing or malformed")
        void testShoulValidate_missingRolesScopes_defaultsEmpty() {
            when(props.issuer()).thenReturn("issuer-A");

            JWTClaimsSet claims = baseClaims("issuer-A", "lanny", "jti-123", List.of("access"));
            when(jwtUtils.validateAndParse("token")).thenReturn(claims);

            JwtClaimsDTO dto = validator.validate("token");

            assertEquals(List.of(), dto.roles());
            assertEquals(List.of(), dto.scopes());
            verify(jwtUtils).validateAndParse("token");
        }
    }

    @Nested
    class StrictSemanticValidation {

        @Test
        @DisplayName("validate() rejects token when issuer does not match configuration")
        void testShouldValidate_invalidIssuer() {
            when(props.issuer()).thenReturn("issuer-EXPECTED");

            JWTClaimsSet claims = baseClaims("issuer-OTHER", "lanny", "jti-123", List.of("access"));
            when(jwtUtils.validateAndParse("token")).thenReturn(claims);

            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> validator.validate("token"));

            assertEquals("Invalid token issuer", ex.getMessage());
        }

        @Test
        @DisplayName("validate() rejects token when subject is missing/blank")
        void testShouldValidate_missingSubject() {
            when(props.issuer()).thenReturn("issuer-A");

            JWTClaimsSet claims = baseClaims("issuer-A", "   ", "jti-123", List.of("access"));
            when(jwtUtils.validateAndParse("token")).thenReturn(claims);

            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> validator.validate("token"));

            assertEquals("Missing subject", ex.getMessage());
        }

        @Test
        @DisplayName("validate() rejects token when jti is missing/blank")
        void testShouldValidate_missingJti() {
            when(props.issuer()).thenReturn("issuer-A");

            JWTClaimsSet claims = baseClaims("issuer-A", "lanny", "   ", List.of("access"));
            when(jwtUtils.validateAndParse("token")).thenReturn(claims);

            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> validator.validate("token"));

            assertEquals("Missing jti", ex.getMessage());
        }

        @Test
        @DisplayName("validate() rejects token when audience is missing/empty")
        void testShouldValidate_missingAudience() {
            when(props.issuer()).thenReturn("issuer-A");

            JWTClaimsSet claims = baseClaims("issuer-A", "lanny", "jti-123", List.of());
            when(jwtUtils.validateAndParse("token")).thenReturn(claims);

            IllegalArgumentException ex = assertThrows(IllegalArgumentException.class,
                    () -> validator.validate("token"));

            assertEquals("Missing audience", ex.getMessage());
        }
    }

    @Nested
    class DelegationToCryptoValidator {

        @Test
        @DisplayName("validate() delegates cryptographic validation to JwtUtils and propagates its exception")
        void testShouldValidate_propagatesJwtUtilsFailure() {
            when(jwtUtils.validateAndParse("token"))
                    .thenThrow(new SecurityException("Invalid JWT token"));

            SecurityException ex = assertThrows(SecurityException.class,
                    () -> validator.validate("token"));

            assertEquals("Invalid JWT token", ex.getMessage());
            verify(jwtUtils, times(1)).validateAndParse("token");
        }
    }
}
