package com.lanny.spring_security_template.infrastructure.jwt.key.classpath;

import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

/**
 * RSA key provider that loads public/private keys from the classpath.
 *
 * <p>
 * Intended exclusively for <b>dev</b> and <b>test</b> profiles.
 * Production environments must use a secure provider
 * (Keystore, Vault, KMS, etc.).
 * </p>
 */
@Component
@Profile({ "dev", "test" })
public class ClasspathRsaKeyProvider implements RsaKeyProvider {

  private final String kid;
  private final RSAPublicKey publicKey;
  private final RSAPrivateKey privateKey;

  public ClasspathRsaKeyProvider(
      @Value("${security.jwt.kid:dev-rsa-1}") String kid,
      @Value("${security.jwt.public-key-path:keys/rsa-public.pem}") String pubPath,
      @Value("${security.jwt.private-key-path:keys/rsa-private.pem}") String privPath) {

    if (kid == null || kid.isBlank()) {
      throw new IllegalArgumentException("KID (key ID) cannot be null or blank.");
    }

    this.kid = kid;

    try (InputStream pubIs = loadClasspathResource(pubPath);
        InputStream privIs = loadClasspathResource(privPath)) {

      this.publicKey = PemUtils.readPublicKey(pubIs);
      this.privateKey = PemUtils.readPrivateKey(privIs);

      validateKeyPair(publicKey, privateKey);

    } catch (Exception e) {
      throw new IllegalStateException(
          "Failed to load RSA key pair from classpath (profile: dev/test).", e);
    }
  }

  /**
   * Loads a resource from classpath using a normalized absolute path.
   */
  private InputStream loadClasspathResource(String path) {
    String normalized = path.startsWith("/") ? path : "/" + path;

    InputStream is = ClasspathRsaKeyProvider.class
        .getResourceAsStream(normalized);

    if (is == null) {
      throw new IllegalStateException(
          "RSA key file not found in classpath: " + normalized);
    }
    return is;
  }

  /**
   * Validates that public and private RSA keys belong to the same key pair.
   */
  private void validateKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
    if (!publicKey.getModulus().equals(privateKey.getModulus())) {
      throw new IllegalStateException(
          "Public and private RSA keys do not match (modulus mismatch).");
    }
  }

  @Override
  public String keyId() {
    return kid;
  }

  @Override
  public RSAPublicKey publicKey() {
    return publicKey;
  }

  @Override
  public RSAPrivateKey privateKey() {
    return privateKey;
  }
}
