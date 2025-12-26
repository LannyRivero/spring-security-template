# ADR-002: RSA Signature Algorithm as Default for JWT

## Status

**Accepted**

**Date**: 2025-12-26

## Context

JWT tokens require digital signatures to ensure:
- **Authenticity**: Verify the token was issued by our system
- **Integrity**: Detect any tampering with token claims
- **Non-repudiation**: Prove the issuer created the token

The JWT specification (RFC 7518) supports multiple signature algorithms:
- **Symmetric**: HMAC (HS256, HS384, HS512) — single shared secret
- **Asymmetric**: RSA (RS256, RS384, RS512) — public/private key pair
- **Asymmetric**: ECDSA (ES256, ES384, ES512) — elliptic curve cryptography

This template must choose a default algorithm that balances:
- **Security**: Strong cryptographic properties
- **Operational simplicity**: Key distribution and rotation
- **Microservices compatibility**: Multiple services validating tokens
- **Regulatory compliance**: FIPS 140-2, ENS, PCI-DSS requirements

## Decision

We will use **RSA-256 (RS256)** as the **default signature algorithm** for JWT tokens.

### Reasoning

1. **Asymmetric cryptography advantages**:
   - **Token issuer** (auth service) holds the private key
   - **Token consumers** (all microservices) only need the public key
   - Public key can be distributed freely without security risk
   - No shared secret to manage across services

2. **Key rotation simplicity**:
   - Rotate private key without redeploying all services
   - Publish new public key via JWK endpoint
   - Services auto-fetch updated keys

3. **Zero-trust architecture**:
   - Services don't need to trust each other with signing keys
   - Only auth service can issue tokens
   - Prevents privilege escalation attacks

4. **Industry standard**:
   - RSA-256 is the most widely adopted JWT algorithm
   - Supported by all major platforms (AWS, Azure, Google Cloud, Keycloak)
   - FIPS 140-2 compliant implementations available

5. **Tooling and debugging**:
   - Public keys can be shared with developers for local testing
   - jwt.io and other tools natively support RS256
   - Easy integration with API gateways (Kong, NGINX, Traefik)

## Alternatives Considered

### Alternative 1: HMAC-SHA256 (HS256)

**Pros**:
- ✅ Faster signing and verification (symmetric crypto is faster than asymmetric)
- ✅ Simpler key management (single secret)
- ✅ Smaller key size (256 bits vs 2048+ bits for RSA)
- ✅ No complex cryptographic libraries required

**Cons**:
- ❌ **Shared secret problem**: Every service needs the signing key
- ❌ **Security risk**: If any service is compromised, attacker can forge tokens
- ❌ **Key rotation nightmare**: Changing the secret requires redeploying all services simultaneously
- ❌ **No key distribution**: Cannot publish keys for external verification
- ❌ **Privilege escalation risk**: Any service can become an issuer

**Why rejected**: In a microservices architecture, distributing a shared secret to all services violates the **principle of least privilege**. HMAC is only suitable for monolithic applications or when the issuer and verifier are the same service.

### Alternative 2: ECDSA (ES256)

**Pros**:
- ✅ **Smaller keys**: 256-bit ECDSA ≈ 3072-bit RSA (same security)
- ✅ **Faster signing**: Elliptic curve operations are faster than RSA
- ✅ **Modern cryptography**: Based on elliptic curves (quantum-resistant variants exist)
- ✅ Asymmetric (same key distribution benefits as RSA)

**Cons**:
- ❌ **Less universal support**: Not all legacy systems support ECDSA
- ❌ **FIPS complexity**: FIPS 140-2 ECDSA implementations require specific curves (P-256, P-384, P-521)
- ❌ **Tooling maturity**: Fewer libraries and tools compared to RSA
- ❌ **Team familiarity**: RSA is more widely understood by developers

**Why rejected**: While ECDSA is technically superior, **RSA offers broader compatibility** and is better understood by teams. ECDSA is a strong candidate for future migration (see "Future Evolution" below).

### Alternative 3: EdDSA (Ed25519)

**Pros**:
- ✅ Extremely fast signing and verification
- ✅ Small keys and signatures
- ✅ Modern, secure design

**Cons**:
- ❌ **Limited support**: Not in original JWT RFC 7518 (added later in RFC 8037)
- ❌ **Nimbus support**: Requires additional dependencies
- ❌ **Enterprise readiness**: Not FIPS 140-2 certified

**Why rejected**: Cutting-edge but not mature enough for enterprise templates.

## Consequences

### Positive

- ✅ **Secure key distribution**: Public keys can be shared openly (JWK endpoint)
- ✅ **Microservices-ready**: Services only validate, cannot forge tokens
- ✅ **Key rotation without downtime**: Rotate private key, publish new public key
- ✅ **Debugging-friendly**: Developers can verify tokens with public key locally
- ✅ **Industry-standard**: Compatible with all major platforms and tools
- ✅ **Compliance-ready**: FIPS 140-2, PCI-DSS, ENS approved
- ✅ **Future-proof**: RSA will remain supported for decades

### Negative

- ⚠️ **Performance overhead**: RSA signing ~10x slower than HMAC (negligible for auth operations)
- ⚠️ **Key size**: 2048-bit RSA keys are larger than HMAC secrets
- ⚠️ **Complexity**: Requires proper key management infrastructure (keystore, rotation policies)

### Neutral

- ℹ️ HMAC remains available as an option (configurable via profiles)
- ℹ️ Can migrate to ECDSA in the future without breaking clients (algorithm negotiation)

## Implementation Notes

### Key Configuration

**Development/Test**:
```yaml
# application-dev.yml
security:
  jwt:
    algorithm: RSA
    rsa:
      public-key: classpath:keys/public_key.pem
      private-key: classpath:keys/private_key.pem
```

**Production**:
```yaml
# application-prod.yml
security:
  jwt:
    algorithm: RSA
    rsa:
      keystore:
        path: ${JWT_KEYSTORE_PATH}
        password: ${JWT_KEYSTORE_PASSWORD}
        alias: ${JWT_KEY_ALIAS}
```

### Code Location

- **Key providers**: `infrastructure/jwt/key/`
  - `ClasspathRsaKeyProvider.java` (dev/test)
  - `KeystoreRsaKeyProvider.java` (prod)
  - `FileSystemRsaKeyProvider.java` (prod alternative)
- **Token signing**: `infrastructure/jwt/nimbus/NimbusJwtTokenProvider.java`
- **Configuration**: `infrastructure/config/JwtConfig.java`

### Key Generation

```bash
# Generate RSA 2048-bit key pair
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# For production: store in Java Keystore
keytool -genkeypair -alias jwt-key -keyalg RSA -keysize 2048 \
  -keystore keystore.p12 -storetype PKCS12 -validity 3650
```

### JWS Header Example

```java
JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
    .keyID(keyId) // Key identifier for rotation
    .type(JOSEObjectType.JWT)
    .build();
```

## Future Evolution

### Short-term (6-12 months)
- ✅ JWK endpoint for public key distribution (`/.well-known/jwks.json`)
- ✅ Automated key rotation with grace period (support multiple active keys)

### Long-term (1-2 years)
- 🔄 Evaluate ECDSA (ES256) migration for performance gains
- 🔄 Post-quantum cryptography readiness (hybrid RSA+PQC schemes)

### Migration Path to ECDSA

If ECDSA becomes preferred:
1. Add ECDSA key pair alongside RSA
2. Issue tokens with `kid` (key ID) header
3. Publish both keys in JWK endpoint
4. Clients validate using `kid`
5. Gradually deprecate RSA keys

## References

- [RFC 7518 - JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
- [OWASP JWT Cheat Sheet - Algorithm Selection](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html#token-sidejacking)
- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [JWT.io - Algorithms Comparison](https://jwt.io/introduction)
- [Spring Security - JWT RSA Configuration](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)

## Review

**Reviewers**: Security Team, DevOps, Platform Architecture
**Approved by**: CISO, Technical Lead
**Review date**: 2025-12-26
