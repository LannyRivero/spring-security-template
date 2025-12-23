package com.lanny.spring_security_template.infrastructure.jwt.key.classpath;

import com.lanny.spring_security_template.infrastructure.config.SecurityJwtProperties;
import com.lanny.spring_security_template.infrastructure.jwt.key.RsaKeyProvider;
import com.lanny.spring_security_template.infrastructure.jwt.nimbus.PemUtils;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Classpath-based RSA key provider with multi-kid support.
 *
 * <p>
 * Intended exclusively for {@code dev} and {@code test} profiles.
 * Loads RSA keys from classpath resources.
 * </p>
 *
 * <p>
 * Supports:
 * <ul>
 * <li>Single active signing key (activeKid)</li>
 * <li>Multiple verification keys (verificationKids)</li>
 * <li>Zero-downtime key rotation</li>
 * </ul>
 * </p>
 */
@Component
@Profile({ "dev", "test" })
public class ClasspathRsaKeyProvider implements RsaKeyProvider {

  private final String activeKid;
  private final RSAPrivateKey privateKey;
  private final Map<String, RSAPublicKey> verificationKeys;

  public ClasspathRsaKeyProvider(SecurityJwtProperties props) {

    SecurityJwtProperties.RsaProperties rsa = requireRsa(props);

    this.activeKid = requireText(rsa.activeKid(), "security.jwt.rsa.active-kid");

    List<String> verificationKids = rsa.verificationKids();
    if (!verificationKids.contains(activeKid)) {
      throw new IllegalStateException(
          "active-kid must be included in verification-kids");
    }

    this.privateKey = loadPrivateKey(rsa.privateKeyLocation());

    Map<String, RSAPublicKey> pubs = new HashMap<>();
    for (String kid : verificationKids) {
      String path = requireText(
          rsa.publicKeys().get(kid),
          "security.jwt.rsa.public-keys[" + kid + "]");
      pubs.put(kid, loadPublicKey(path));
    }

    this.verificationKeys = Map.copyOf(pubs);
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

  private static SecurityJwtProperties.RsaProperties requireRsa(SecurityJwtProperties props) {
    if (props.rsa() == null) {
      throw new IllegalStateException(
          "RSA configuration is required when algorithm=RSA");
    }
    return props.rsa();
  }

  private RSAPrivateKey loadPrivateKey(String path) {
    try (InputStream is = loadClasspath(path)) {
      return PemUtils.readPrivateKey(is);
    } catch (Exception e) {
      throw new IllegalStateException(
          "Failed to load RSA private key from classpath: " + path, e);
    }
  }

  private RSAPublicKey loadPublicKey(String path) {
    try (InputStream is = loadClasspath(path)) {
      return PemUtils.readPublicKey(is);
    } catch (Exception e) {
      throw new IllegalStateException(
          "Failed to load RSA public key from classpath: " + path, e);
    }
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

  private static String requireText(String value, String property) {
    if (value == null || value.isBlank()) {
      throw new IllegalStateException(property + " must not be null or blank");
    }
    return value;
  }
}
