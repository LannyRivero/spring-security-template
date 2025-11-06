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
 * Loads RSA keys from the classpath for dev/test profiles.
 * 
 * Example configuration:
 * security.jwt.kid=dev-rsa-1
 * security.jwt.public-key-path=keys/rsa-public.pem
 * security.jwt.private-key-path=keys/rsa-private.pem
 */
@Component
@Profile({"dev", "test"})
public class ClasspathRsaKeyProvider implements RsaKeyProvider {

  private final String kid;
  private final RSAPublicKey pub;
  private final RSAPrivateKey priv;

   public ClasspathRsaKeyProvider() {
    this("test-rsa", "keys/rsa-public.pem", "keys/rsa-private.pem");
  }

  public ClasspathRsaKeyProvider(
      @Value("${security.jwt.kid:dev-rsa-1}") String kid,
      @Value("${security.jwt.public-key-path:keys/rsa-public.pem}") String pubPath,
      @Value("${security.jwt.private-key-path:keys/rsa-private.pem}") String privPath
  ) {
    this.kid = kid;
    try (InputStream pubIs = resource(pubPath);
         InputStream privIs = resource(privPath)) {
      this.pub  = PemUtils.readPublicKey(pubIs);
      this.priv = PemUtils.readPrivateKey(privIs);
    } catch (Exception e) {
      throw new IllegalStateException("Cannot load RSA keys from classpath", e);
    }
  }

  private InputStream resource(String path) {
    var is = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
    if (is == null)
      throw new IllegalStateException("Resource not found: " + path);
    return is;
  }

  @Override public String keyId() { return kid; }
  @Override public RSAPublicKey publicKey() { return pub; }
  @Override public RSAPrivateKey privateKey() { return priv; }
}
