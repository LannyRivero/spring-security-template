package com.lanny.spring_security_template.jwt;

import static org.junit.jupiter.api.Assertions.*;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * ✅ Integration-style test: validates RSA keypair + RS256 JWT creation and verification. Uses the
 * demo keys from src/main/resources/keys.
 */
class JwtUtilsTest {

  private RSAPrivateKey loadPrivateKey() throws Exception {
    try (InputStream is = getClass().getClassLoader().getResourceAsStream("keys/rsa-private.pem")) {
      if (is == null) throw new IllegalStateException("Private key not found in resources");

      String pem =
          new String(is.readAllBytes())
              .replace("-----BEGIN RSA PRIVATE KEY-----", "")
              .replace("-----END RSA PRIVATE KEY-----", "")
              .replace("-----BEGIN PRIVATE KEY-----", "")
              .replace("-----END PRIVATE KEY-----", "")
              .replaceAll("\\s", ""); // elimina espacios y saltos de línea

      byte[] keyBytes = Base64.getDecoder().decode(pem);

      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
      return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    }
  }

  private RSAPublicKey loadPublicKey() throws Exception {
    try (InputStream is = getClass().getClassLoader().getResourceAsStream("keys/rsa-public.pem")) {
      String pem = new String(is.readAllBytes());
      String clean = pem.replaceAll("-----\\w+ PUBLIC KEY-----", "").replaceAll("\\s", "");
      byte[] bytes = Base64.getDecoder().decode(clean);
      var spec = new X509EncodedKeySpec(bytes);
      return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }
  }

  @Test
  @DisplayName("🔐 Should generate and verify a valid RS256 JWT using local RSA keys")
  void testGenerateAndVerifyJwt() throws Exception {
    // Load keys
    RSAPrivateKey privateKey = loadPrivateKey();
    RSAPublicKey publicKey = loadPublicKey();

    // Build claims
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

    // Sign with private key
    SignedJWT signedJWT =
        new SignedJWT(
            new JWSHeader.Builder(JWSAlgorithm.RS256).type(JOSEObjectType.JWT).build(), claims);
    signedJWT.sign(new RSASSASigner(privateKey));

    String token = signedJWT.serialize();
    assertNotNull(token);
    assertTrue(token.split("\\.").length == 3, "JWT must have 3 parts");

    // Verify with public key
    SignedJWT parsed = SignedJWT.parse(token);
    boolean verified = parsed.verify(new RSASSAVerifier(publicKey));

    assertTrue(verified, "Token signature must be valid");
    assertEquals("user123", parsed.getJWTClaimsSet().getSubject());
    assertEquals("security-template", parsed.getJWTClaimsSet().getIssuer());
  }
}
