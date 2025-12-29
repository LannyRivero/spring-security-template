package com.lanny.spring_security_template.infrastructure.jwt.key.classpath;

import com.lanny.spring_security_template.infrastructure.config.JwtAlgorithm;
import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.Map;

/**
 * RSA Key Provider loading keys from the application classpath.
 *
 * <p>
 * Intended for development and test environments.
 * Uses PEM-encoded keys bundled with the application.
 * </p>
 *
 * <p>
 * Selection is controlled via:
 * 
 * <pre>
 * security.jwt.rsa.source = classpath
 * </pre>
 * </p>
 */
@Component
@ConditionalOnProperty(prefix = "security.jwt.rsa", name = "source", havingValue = "classpath")
public class ClasspathRsaKeyProvider implements RsaKeyProvider {

  private final String activeKid;
  private final RSAPrivateKey privateKey;
  private final Map<String, RSAPublicKey> verificationKeys;

  public ClasspathRsaKeyProvider(SecurityJwtProperties props) {

    if (props.algorithm() != JwtAlgorithm.RSA) {
      throw new IllegalStateException(
          "ClasspathRsaKeyProvider requires algorithm=RSA");
    }

    SecurityJwtProperties.RsaProperties rsa = props.rsa();
    if (rsa == null) {
      throw new IllegalStateException(
          "RSA configuration is required when algorithm=RSA");
    }

    this.activeKid = rsa.activeKid();
    this.privateKey = loadPrivateKey(rsa.privateKeyLocation());
    this.verificationKeys = loadPublicKeys(rsa);
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
  // Key loading
  // ======================================================

  private RSAPrivateKey loadPrivateKey(String path) {
    try (InputStream is = loadClasspath(path)) {
      return PemUtils.readPrivateKey(is);
    } catch (Exception e) {
      throw new IllegalStateException(
          "Failed to load RSA private key from classpath: " + path, e);
    }
  }

  private Map<String, RSAPublicKey> loadPublicKeys(SecurityJwtProperties.RsaProperties rsa) {

    Map<String, RSAPublicKey> keys = new HashMap<>();

    for (String kid : rsa.verificationKids()) {
      String path = rsa.publicKeys().get(kid);
      if (path == null || path.isBlank()) {
        throw new IllegalStateException(
            "Missing public key for kid: " + kid);
      }

      try (InputStream is = loadClasspath(path)) {
        keys.put(kid, PemUtils.readPublicKey(is));
      } catch (Exception e) {
        throw new IllegalStateException(
            "Failed to load RSA public key for kid=" + kid, e);
      }
    }

    return Map.copyOf(keys);
  }

  private InputStream loadClasspath(String path) {
    String normalized = path.startsWith("/") ? path : "/" + path;
    InputStream is = getClass().getResourceAsStream(normalized);
    if (is == null) {
      throw new IllegalStateException(
          "RSA key not found in classpath: " + normalized);
    }
    return is;
  }
}
