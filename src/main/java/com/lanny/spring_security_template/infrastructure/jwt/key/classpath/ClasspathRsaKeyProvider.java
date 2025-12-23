package com.lanny.spring_security_template.infrastructure.jwt.key.classpath;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;

/**
 * RSA key provider that loads keys from the classpath.
 *
 * <p>
 * DEV / TEST only.
 * Single-key implementation adapted to multi-kid contract.
 * </p>
 */
@Component
@Profile({ "dev", "test" })
public class ClasspathRsaKeyProvider implements RsaKeyProvider {

  private final String activeKid;
  private final RSAPrivateKey privateKey;
  private final Map<String, RSAPublicKey> verificationKeys;

  public ClasspathRsaKeyProvider(
      @Value("${security.jwt.kid:dev-rsa-1}") String kid,
      @Value("${security.jwt.public-key-path:keys/rsa-public.pem}") String pubPath,
      @Value("${security.jwt.private-key-path:keys/rsa-private.pem}") String privPath) {

    this.activeKid = requireText(kid, "security.jwt.kid");

    try (InputStream pubIs = loadClasspathResource(pubPath);
        InputStream privIs = loadClasspathResource(privPath)) {

      RSAPublicKey publicKey = PemUtils.readPublicKey(pubIs);
      RSAPrivateKey privateKey = PemUtils.readPrivateKey(privIs);

      validateKeyPair(publicKey, privateKey);

      this.privateKey = privateKey;

      // 🔑 Single kid, but multi-kid ready
      this.verificationKeys = Map.of(this.activeKid, publicKey);

    } catch (Exception e) {
      throw new IllegalStateException(
          "Failed to load RSA key pair from classpath (profile: dev/test).", e);
    }
  }

  // ======================================================
  // RsaKeyProvider
  // ======================================================

  @Override
  public String activeKid() {
    return activeKid;
  }

  @Override
  public RSAPrivateKey privateKey() {
    return privateKey;
  }

  @Override
  public Map<String, RSAPublicKey> verificationKeys() {
    return verificationKeys;
  }

  // ======================================================
  // Internals
  // ======================================================

  private InputStream loadClasspathResource(String path) {
    String normalized = path.startsWith("/") ? path : "/" + path;
    InputStream is = ClasspathRsaKeyProvider.class.getResourceAsStream(normalized);

    if (is == null) {
      throw new IllegalStateException(
          "RSA key file not found in classpath: " + normalized);
    }
    return is;
  }

  private static void validateKeyPair(
      RSAPublicKey publicKey,
      RSAPrivateKey privateKey) {

    if (!publicKey.getModulus().equals(privateKey.getModulus())) {
      throw new IllegalStateException(
          "Public and private RSA keys do not match (modulus mismatch).");
    }
  }

  private static String requireText(String value, String property) {
    if (value == null || value.isBlank()) {
      throw new IllegalStateException(property + " must not be null or blank.");
    }
    return value;
  }
}
