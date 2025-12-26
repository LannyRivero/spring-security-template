# ADR-005: Cryptographic Key Management Strategy

## Status

**Accepted**

**Date**: 2025-12-26

## Context

JWT tokens signed with RSA (ADR-002) require secure management of:
- **Private keys**: Used to sign tokens (must remain secret)
- **Public keys**: Used to verify tokens (can be distributed)

Key management must address:
- **Storage**: Where and how are keys stored?
- **Access control**: Who can access private keys?
- **Rotation**: How to update keys without service disruption?
- **Environment separation**: Different keys for dev/test/prod
- **Compliance**: Meet FIPS 140-2, PCI-DSS, ISO 27001 requirements
- **Operational simplicity**: Easy for developers, secure for production

Challenges:
- **Development**: Developers need keys for local testing
- **CI/CD**: Build pipelines need keys for integration tests
- **Production**: Keys must never be committed to git or exposed
- **Disaster recovery**: Keys must be backed up securely
- **Multi-region**: Keys must be accessible across deployments

## Decision

We will implement **Profile-Based Key Provider Strategy** with multiple implementations:

1. **Development/Test**: Classpath-based (embedded keys)
2. **Production**: Keystore-based or External Secrets Manager
3. **Abstraction**: `RsaKeyProvider` interface (infrastructure port)

### Key Providers by Profile

| Profile | Provider | Storage | Use Case |
|---------|----------|---------|----------|
| `dev` | `ClasspathRsaKeyProvider` | `/src/main/resources/keys/*.pem` | Local development |
| `test` | `ClasspathRsaKeyProvider` | `/src/test/resources/keys/*.pem` | Unit/integration tests |
| `demo` | `ClasspathRsaKeyProvider` | Embedded demo keys | Demos, POCs |
| `prod` | `KeystoreRsaKeyProvider` | Java Keystore (PKCS12) | Production (file-based) |
| `prod` | `FileSystemRsaKeyProvider` | Filesystem (PEM) | Production (alternative) |
| `prod` (future) | `AwsKmsKeyProvider` | AWS Secrets Manager | Cloud-native (AWS) |
| `prod` (future) | `VaultKeyProvider` | HashiCorp Vault | Enterprise secrets |

### Architecture

```
application/auth/port/out/
└── RsaKeyProvider.java (interface)

infrastructure/jwt/key/
├── classpath/
│   └── ClasspathRsaKeyProvider.java       # @Profile({"dev", "test"})
├── keystore/
│   └── KeystoreRsaKeyProvider.java        # @Profile("prod")
├── file/
│   └── FileSystemRsaKeyProvider.java      # @Profile("prod")
└── kms/ (future)
    ├── AwsKmsKeyProvider.java
    └── VaultKeyProvider.java
```

## Alternatives Considered

### Alternative 1: Hardcoded Keys in Code

**Approach**: Keys embedded as string constants in Java code.

**Pros**:
- ✅ Simple, no external files
- ✅ Works everywhere

**Cons**:
- ❌ **CRITICAL SECURITY VIOLATION**: Keys in source control
- ❌ **Immutable**: Cannot rotate without recompiling
- ❌ **Compliance failure**: Violates every security standard
- ❌ **Audit nightmare**: Keys exposed in git history forever

**Why rejected**: **Unacceptable security risk**. Never hardcode secrets.

### Alternative 2: Environment Variables Only

**Approach**: Load keys from `JWT_PRIVATE_KEY` and `JWT_PUBLIC_KEY` env vars.

**Pros**:
- ✅ Not in source control
- ✅ 12-factor app compliant
- ✅ Works in containers and Kubernetes

**Cons**:
- ⚠️ **PEM encoding issues**: Newlines in env vars are problematic
- ⚠️ **Security risk**: Env vars visible in process listings (`ps aux`)
- ⚠️ **Limited rotation**: Requires service restart
- ⚠️ **No centralized management**: Each service manages its own

**Why not primary**: While useful, env vars alone don't provide enterprise-grade key management (no rotation, no audit, no centralization). **Acceptable as fallback**.

### Alternative 3: Single Key Provider (Keystore Only)

**Approach**: Use Java Keystore everywhere, including dev.

**Pros**:
- ✅ Single implementation (less code)
- ✅ Production-ready everywhere

**Cons**:
- ❌ **Developer friction**: Keystore setup is complex for local dev
- ❌ **CI/CD complexity**: Requires distributing keystore to pipelines
- ❌ **Documentation burden**: Every developer needs keystore tutorial

**Why rejected**: **Developer experience matters**. Classpath keys for dev + keystore for prod is optimal.

### Alternative 4: Embedded Database (H2) for Keys

**Approach**: Store keys in application database.

**Cons**:
- ❌ **Circular dependency**: Database needs to be up before app starts
- ❌ **Backup complexity**: Keys scattered across databases
- ❌ **Security risk**: Keys in application database (same attack surface)

**Why rejected**: Keys should be **infrastructure-level secrets**, not application data.

## Consequences

### Positive

- ✅ **Developer-friendly**: Local dev works out of the box (no setup)
- ✅ **Production-secure**: Keys never committed, managed externally
- ✅ **Testable**: Test keys isolated from production keys
- ✅ **Flexible**: Swap providers without changing application code
- ✅ **Rotation-ready**: Interface supports key versioning (kid - Key ID)
- ✅ **Cloud-ready**: Easy to add AWS KMS or Vault provider later
- ✅ **Compliance**: Separation of concerns (dev vs prod keys)

### Negative

- ⚠️ **Multiple implementations**: Maintenance overhead for each provider
- ⚠️ **Configuration complexity**: Must document setup for each profile
- ⚠️ **Testing burden**: Each provider needs integration tests

### Neutral

- ℹ️ Demo keys checked into git (acceptable, clearly marked as insecure)
- ℹ️ Production keys NEVER in git (enforced by `.gitignore` and pre-commit hooks)

## Implementation Notes

### Port Interface

```java
public interface RsaKeyProvider {
    /**
     * Returns the RSA private key for signing tokens.
     * @param keyId optional key identifier (for rotation)
     */
    RSAPrivateKey getPrivateKey(String keyId);
    
    /**
     * Returns the RSA public key for verifying tokens.
     * @param keyId optional key identifier (for rotation)
     */
    RSAPublicKey getPublicKey(String keyId);
    
    /**
     * Returns the default key ID.
     */
    String getDefaultKeyId();
}
```

### Development Setup (Classpath)

**Configuration** (`application-dev.yml`):
```yaml
security:
  jwt:
    algorithm: RSA
    rsa:
      public-key: classpath:keys/public_key.pem
      private-key: classpath:keys/private_key.pem
```

**Implementation**:
```java
@Component
@Profile({"dev", "test"})
@RequiredArgsConstructor
public class ClasspathRsaKeyProvider implements RsaKeyProvider {
    private final JwtRsaProperties properties;
    
    @Override
    public RSAPrivateKey getPrivateKey(String keyId) {
        Resource resource = resourceLoader.getResource(properties.getPrivateKey());
        return loadPrivateKeyFromPem(resource);
    }
    
    @Override
    public RSAPublicKey getPublicKey(String keyId) {
        Resource resource = resourceLoader.getResource(properties.getPublicKey());
        return loadPublicKeyFromPem(resource);
    }
}
```

**Key Generation** (for new projects):
```bash
# Generate 2048-bit RSA key pair
openssl genrsa -out private_key.pem 2048
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Place in src/main/resources/keys/
mkdir -p src/main/resources/keys
mv private_key.pem src/main/resources/keys/
mv public_key.pem src/main/resources/keys/
```

**`.gitignore`** (prevent accidental commits):
```gitignore
# Allow dev keys (demo purposes)
!src/main/resources/keys/public_key.pem
!src/main/resources/keys/private_key.pem

# Block production keys
*.p12
*.jks
*.keystore
**/prod-keys/
```

### Production Setup (Keystore)

**Configuration** (`application-prod.yml`):
```yaml
security:
  jwt:
    algorithm: RSA
    rsa:
      keystore:
        path: ${JWT_KEYSTORE_PATH}             # /opt/app/keystore.p12
        password: ${JWT_KEYSTORE_PASSWORD}     # From secrets manager
        alias: ${JWT_KEY_ALIAS:jwt-signing-key}
        type: PKCS12
```

**Implementation**:
```java
@Component
@Profile("prod")
@RequiredArgsConstructor
public class KeystoreRsaKeyProvider implements RsaKeyProvider {
    private final JwtKeystoreProperties properties;
    
    @Override
    public RSAPrivateKey getPrivateKey(String keyId) {
        KeyStore keystore = loadKeyStore();
        Key key = keystore.getKey(
            properties.getAlias(),
            properties.getPassword().toCharArray()
        );
        return (RSAPrivateKey) key;
    }
    
    @Override
    public RSAPublicKey getPublicKey(String keyId) {
        KeyStore keystore = loadKeyStore();
        Certificate cert = keystore.getCertificate(properties.getAlias());
        return (RSAPublicKey) cert.getPublicKey();
    }
    
    private KeyStore loadKeyStore() {
        KeyStore ks = KeyStore.getInstance(properties.getType());
        try (InputStream is = new FileInputStream(properties.getPath())) {
            ks.load(is, properties.getPassword().toCharArray());
        }
        return ks;
    }
}
```

**Keystore Generation**:
```bash
# Create PKCS12 keystore with RSA key
keytool -genkeypair \
  -alias jwt-signing-key \
  -keyalg RSA \
  -keysize 2048 \
  -storetype PKCS12 \
  -keystore keystore.p12 \
  -validity 3650 \
  -storepass changeit \
  -dname "CN=JWT Signing Key, OU=Security, O=Company, L=City, ST=State, C=US"

# Export public key for distribution
keytool -exportcert \
  -alias jwt-signing-key \
  -keystore keystore.p12 \
  -storetype PKCS12 \
  -storepass changeit \
  -rfc \
  -file public_key.pem
```

**Deployment**:
```bash
# Kubernetes Secret
kubectl create secret generic jwt-keystore \
  --from-file=keystore.p12 \
  --namespace=production

# Docker volume mount
docker run -v /secure/keystore.p12:/opt/app/keystore.p12 \
  -e JWT_KEYSTORE_PATH=/opt/app/keystore.p12 \
  -e JWT_KEYSTORE_PASSWORD=${KEYSTORE_PASSWORD} \
  spring-security-template:latest
```

### Production Setup (Filesystem - PEM)

**Alternative for environments where keystore is inconvenient**.

**Configuration** (`application-prod.yml`):
```yaml
security:
  jwt:
    algorithm: RSA
    rsa:
      public-key: file:/opt/app/keys/public_key.pem
      private-key: file:/opt/app/keys/private_key.pem
```

**Implementation**:
```java
@Component
@Profile("prod")
@ConditionalOnProperty(prefix = "security.jwt.rsa", name = "public-key")
public class FileSystemRsaKeyProvider implements RsaKeyProvider {
    // Similar to ClasspathRsaKeyProvider but loads from filesystem
}
```

### Future: AWS KMS Integration

```yaml
# application-prod-aws.yml
security:
  jwt:
    algorithm: RSA
    rsa:
      kms:
        region: us-east-1
        key-id: arn:aws:kms:us-east-1:123456789:key/abc-123
```

```java
@Component
@Profile("prod-aws")
public class AwsKmsKeyProvider implements RsaKeyProvider {
    private final AWSKMS kmsClient;
    
    @Override
    public RSAPrivateKey getPrivateKey(String keyId) {
        // KMS doesn't expose private key — sign in KMS
        throw new UnsupportedOperationException(
            "Use KMS sign operation directly"
        );
    }
    
    @Override
    public RSAPublicKey getPublicKey(String keyId) {
        GetPublicKeyRequest request = new GetPublicKeyRequest()
            .withKeyId(keyId);
        GetPublicKeyResult result = kmsClient.getPublicKey(request);
        return parsePublicKey(result.getPublicKey());
    }
}
```

## Key Rotation Strategy

### Rotation Process

1. **Generate new key pair** (new `kid` = `key-v2`)
2. **Deploy new key** to keystore/secrets manager
3. **Update configuration** to include both keys
4. **Issue new tokens** with `kid: key-v2`
5. **Grace period** (e.g., 7 days) — validate with both keys
6. **Retire old key** (`key-v1`) after grace period

### JWK Endpoint (Public Key Distribution)

```java
@RestController
@RequestMapping("/.well-known")
public class JwkController {
    private final RsaKeyProvider keyProvider;
    
    @GetMapping("/jwks.json")
    public Map<String, Object> getJwks() {
        RSAPublicKey publicKey = keyProvider.getPublicKey(null);
        
        return Map.of(
            "keys", List.of(
                Map.of(
                    "kty", "RSA",
                    "kid", keyProvider.getDefaultKeyId(),
                    "use", "sig",
                    "alg", "RS256",
                    "n", Base64.getUrlEncoder().encodeToString(publicKey.getModulus().toByteArray()),
                    "e", Base64.getUrlEncoder().encodeToString(publicKey.getPublicExponent().toByteArray())
                )
            )
        );
    }
}
```

## Security Checklist

- [ ] Private keys NEVER committed to git
- [ ] `.gitignore` configured to block keystore files
- [ ] Pre-commit hooks validate no secrets in commits
- [ ] Production keystore password stored in secrets manager (not env vars)
- [ ] File permissions: `chmod 600` for private keys (Linux)
- [ ] Key rotation documented and tested
- [ ] Backup strategy for production keys
- [ ] Disaster recovery plan (key loss scenario)

## Testing

```java
@SpringBootTest
@ActiveProfiles("dev")
class ClasspathRsaKeyProviderTest {
    @Autowired RsaKeyProvider keyProvider;
    
    @Test
    void shouldLoadKeysFromClasspath() {
        RSAPrivateKey privateKey = keyProvider.getPrivateKey(null);
        RSAPublicKey publicKey = keyProvider.getPublicKey(null);
        
        assertThat(privateKey).isNotNull();
        assertThat(publicKey).isNotNull();
        assertThat(privateKey.getAlgorithm()).isEqualTo("RSA");
    }
    
    @Test
    void shouldSignAndVerifyWithLoadedKeys() {
        // Test signing and verification round-trip
    }
}
```

## References

- [NIST SP 800-57 - Key Management](https://csrc.nist.gov/publications/detail/sp/800-57-part-1/rev-5/final)
- [OWASP Cryptographic Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [AWS KMS Best Practices](https://docs.aws.amazon.com/kms/latest/developerguide/best-practices.html)
- [HashiCorp Vault - Key Management](https://www.vaultproject.io/)
- [RFC 7517 - JSON Web Key (JWK)](https://datatracker.ietf.org/doc/html/rfc7517)

## Review

**Reviewers**: Security Team, DevOps, Platform Architects
**Approved by**: CISO, Operations Lead
**Review date**: 2025-12-26
