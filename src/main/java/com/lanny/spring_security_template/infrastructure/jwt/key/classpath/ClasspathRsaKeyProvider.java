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
 * This implementation is intended exclusively for <b>dev</b> and <b>test</b>
 * environments. For production, use a secure provider (e.g., keystore,
 * Hashicorp Vault, AWS KMS, Azure KeyVault, GCP KMS).
 * </p>
 */
@Component
@Profile({ "dev", "test" })
public class ClasspathRsaKeyProvider implements RsaKeyProvider {

  private final String kid;
  private final RSAPublicKey publicKey;
  private final RSAPrivateKey privateKey;

  /**
   * Constructor loading RSA keys from classpath locations provided in
   * configuration properties.
   */
  public ClasspathRsaKeyProvider(
      @Value("${security.jwt.kid:dev-rsa-1}") String kid,
      @Value("${security.jwt.public-key-path:keys/rsa-public.pem}") String pubPath,
      @Value("${security.jwt.private-key-path:keys/rsa-private.pem}") String privPath) {
    if (kid == null || kid.isBlank()) {
      throw new IllegalArgumentException("KID (key ID) cannot be null or blank.");
    }

    this.kid = kid;

    try (InputStream pubIs = loadResource(pubPath);
        InputStream privIs = loadResource(privPath)) {

      this.publicKey = PemUtils.readPublicKey(pubIs);
      this.privateKey = PemUtils.readPrivateKey(privIs);

    } catch (Exception e) {
      throw new IllegalStateException("Failed to load RSA keys from classpath.", e);
    }
  }

  /** Loads a classpath resource or fails fast. */
  private InputStream loadResource(String path) {
    InputStream is = Thread.currentThread()
        .getContextClassLoader()
        .getResourceAsStream(path);

    if (is == null) {
      throw new IllegalStateException("RSA key file not found in classpath: " + path);
    }
    return is;
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
