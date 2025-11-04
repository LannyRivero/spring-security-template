package com.lanny.spring_security_template.jwt;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * ✅ Integration test: validates JWT creation and verification using HS256 (HMAC) with a randomly
 * generated 256-bit secret.
 *
 * <p>This test complements JwtUtilsTest (RS256) by covering the symmetric algorithm variant. It
 * ensures HMAC tokens can be securely generated and verified without relying on external
 * configuration.
 */
class JwtUtilsHmacTest {

  @Test
  @DisplayName("Should generate and verify a valid HS256 JWT using a random secret")
  void testGenerateAndVerifyHmacJwt() throws Exception {
    // Generate a secure random 256-bit secret (32 bytes)
    byte[] secretBytes = new byte[32];
    new SecureRandom().nextBytes(secretBytes);

    // Build JWT claims
    Instant now = Instant.now();
    JWTClaimsSet claims =
        new JWTClaimsSet.Builder()
            .subject("user123")
            .issuer("security-template")
            .issueTime(Date.from(now))
            .expirationTime(Date.from(now.plusSeconds(60)))
            .jwtID(UUID.randomUUID().toString())
            .claim("roles", List.of("ROLE_USER"))
            .claim("scopes", List.of("profile:read"))
            .build();

    // Sign token using HS256 and the random secret
    SignedJWT signedJWT =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.HS256).type(JOSEObjectType.JWT).build(), claims);
    signedJWT.sign(new MACSigner(secretBytes));

    String token = signedJWT.serialize();
    assertNotNull(token);
    assertEquals(3, token.split("\\.").length, "JWT must contain 3 parts");

    // Verify token using the same secret
    SignedJWT parsed = SignedJWT.parse(token);
    boolean verified = parsed.verify(new MACVerifier(secretBytes));

    assertTrue(verified, "Token signature must be valid");
    assertEquals("user123", parsed.getJWTClaimsSet().getSubject());
    assertEquals("security-template", parsed.getJWTClaimsSet().getIssuer());
  }
}
