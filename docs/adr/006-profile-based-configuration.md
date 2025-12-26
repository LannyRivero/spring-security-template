# ADR-006: Profile-Based Configuration Strategy

## Status

**Accepted**

**Date**: 2025-12-26

## Context

Spring Boot applications require different configurations across environments:
- **Development**: Fast feedback, embedded databases, verbose logging, demo data
- **Test**: Isolated, repeatable, in-memory dependencies, fast execution
- **Demo**: Realistic but safe data, showcasing features, relaxed security for POCs
- **Production**: Performance-optimized, external dependencies, strict security, monitoring

Challenges:
- **Dependency conflicts**: Dev uses H2, prod uses PostgreSQL
- **Security trade-offs**: Dev needs accessible keys, prod requires secrets managers
- **Performance**: Dev tolerates slower startup, prod needs fast boot
- **Data isolation**: Test data must not pollute prod databases
- **Behavioral differences**: Dev allows anonymous access for Swagger, prod blocks it

We need a strategy that:
- **Separates concerns** clearly between environments
- **Prevents prod misconfigurations** from leaking into dev
- **Enables safe feature toggles** (e.g., Redis blacklist only in prod)
- **Documents** what each profile is for
- **Enforces** profile selection (no ambiguous "default" behavior)

## Decision

We will implement **Four Distinct Spring Profiles** with clear responsibilities:

| Profile | Purpose | Active In | Key Characteristics |
|---------|---------|-----------|---------------------|
| **dev** | Local development | Developer laptops | Classpath keys, H2 database, demo users, verbose logs, Swagger enabled |
| **test** | Automated testing | CI/CD pipelines | In-memory data, test fixtures, isolated clock, fast startup |
| **demo** | Proof-of-concepts | Demo environments | Embedded Redis, safe sample data, relaxed rate limits, monitoring enabled |
| **prod** | Production workloads | Live environments | External secrets, PostgreSQL/MySQL, Redis cluster, strict security, optimized |

### Profile Selection Strategy

- **Default profile**: `dev` (safe for local development)
- **Explicit activation**: Required in prod (no implicit prod activation)
- **Fail-fast**: Application refuses to start if conflicting profiles are active

## Alternatives Considered

### Alternative 1: Single Profile (No Differentiation)

**Approach**: Same configuration everywhere, toggle via properties.

**Pros**:
- ✅ Simplest approach
- ✅ No profile management

**Cons**:
- ❌ **Configuration bloat**: Single file with all environments
- ❌ **Accidental prod changes**: Easy to break prod by changing dev config
- ❌ **No safety nets**: Can't enforce profile-specific constraints

**Why rejected**: **Too risky**. Production and development have fundamentally different needs.

### Alternative 2: Many Fine-Grained Profiles

**Approach**: `dev-local`, `dev-docker`, `test-unit`, `test-integration`, `prod-aws`, `prod-azure`, etc.

**Pros**:
- ✅ Maximum flexibility

**Cons**:
- ❌ **Complexity explosion**: Hard to understand which profiles do what
- ❌ **Maintenance nightmare**: Changes ripple across many files
- ❌ **Documentation burden**: Each profile needs docs

**Why rejected**: **Over-engineering**. Four profiles cover all use cases. Cloud-specific config goes in separate property files (`application-prod-aws.yml`), not profiles.

### Alternative 3: Environment Variables Only (No Profiles)

**Approach**: Everything configured via env vars, no profile files.

**Pros**:
- ✅ 12-factor app compliant
- ✅ Works in containers

**Cons**:
- ❌ **Developer friction**: Must set 20+ env vars for local dev
- ❌ **No defaults**: Can't have reasonable dev defaults
- ❌ **Verbose**: Env vars everywhere

**Why rejected**: **Poor developer experience**. Profiles provide sensible defaults. Env vars override profiles when needed.

## Consequences

### Positive

- ✅ **Clear separation**: Each profile has a single responsibility
- ✅ **Safe defaults**: Dev profile works out of the box
- ✅ **Easy testing**: Test profile is isolated and fast
- ✅ **Production safety**: Prod profile enforces strict security
- ✅ **Gradual transition**: Demo profile bridges dev and prod
- ✅ **Documentation**: Profile names are self-explanatory
- ✅ **Conditional beans**: Use `@Profile` for environment-specific components

### Negative

- ⚠️ **Configuration duplication**: Some properties repeated across profiles
- ⚠️ **Profile discipline**: Developers must remember to activate correct profile

### Neutral

- ℹ️ Can combine profiles (`dev,demo`) for specific scenarios
- ℹ️ Profiles can inherit common config from `application.yml`

## Implementation Notes

### Profile Structure

```
src/main/resources/
├── application.yml              # Common config (all profiles)
├── application-dev.yml          # Development-specific
├── application-test.yml         # Testing-specific
├── application-demo.yml         # Demo-specific
├── application-prod.yml         # Production-specific
├── application-prod-aws.yml     # Production on AWS (optional)
└── application-prod-azure.yml   # Production on Azure (optional)
```

### Common Configuration (`application.yml`)

```yaml
spring:
  application:
    name: spring-security-template
  profiles:
    active: dev  # Default profile

logging:
  level:
    root: INFO
    org.springframework.security: INFO

management:
  endpoints:
    web:
      exposure:
        include: health,info
```

### Development Profile (`application-dev.yml`)

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:devdb
    username: sa
    password: 
  jpa:
    show-sql: true
    hibernate:
      ddl-auto: create-drop
  h2:
    console:
      enabled: true

security:
  jwt:
    algorithm: RSA
    rsa:
      public-key: classpath:keys/public_key.pem
      private-key: classpath:keys/private_key.pem
    access-token-ttl: 60m
    refresh-token-ttl: 30d

logging:
  level:
    com.lanny.spring_security_template: DEBUG

springdoc:
  swagger-ui:
    enabled: true
```

### Test Profile (`application-test.yml`)

```yaml
spring:
  datasource:
    url: jdbc:h2:mem:testdb
    username: sa
    password: 
  jpa:
    hibernate:
      ddl-auto: create-drop

security:
  jwt:
    access-token-ttl: 5m  # Faster tests
    refresh-token-ttl: 10m

logging:
  level:
    root: WARN
    com.lanny.spring_security_template: INFO
```

### Demo Profile (`application-demo.yml`)

```yaml
spring:
  datasource:
    url: jdbc:postgresql://localhost:5432/demo
    username: demo_user
    password: ${DB_PASSWORD}

security:
  jwt:
    algorithm: RSA
    rsa:
      keystore:
        path: classpath:keys/demo-keystore.p12
        password: ${JWT_KEYSTORE_PASSWORD}

  rate-limit:
    login:
      requests-per-minute: 10  # Relaxed for demos

management:
  endpoints:
    web:
      exposure:
        include: health,info,prometheus

springdoc:
  swagger-ui:
    enabled: true
```

### Production Profile (`application-prod.yml`)

```yaml
spring:
  datasource:
    url: ${DB_URL}
    username: ${DB_USERNAME}
    password: ${DB_PASSWORD}
    hikari:
      maximum-pool-size: 20
      minimum-idle: 5
  jpa:
    hibernate:
      ddl-auto: validate  # Never auto-create in prod
    show-sql: false

security:
  jwt:
    algorithm: RSA
    rsa:
      keystore:
        path: ${JWT_KEYSTORE_PATH}
        password: ${JWT_KEYSTORE_PASSWORD}
        alias: ${JWT_KEY_ALIAS}
    access-token-ttl: 15m  # Short-lived in prod
    refresh-token-ttl: 7d

  rate-limit:
    login:
      requests-per-minute: 3  # Strict rate limiting

logging:
  level:
    root: WARN
    com.lanny.spring_security_template: INFO

management:
  endpoints:
    web:
      exposure:
        include: health,prometheus

springdoc:
  swagger-ui:
    enabled: false  # No Swagger in prod
```

### Profile-Specific Beans

```java
// Dev/Test: In-memory blacklist
@Component
@Profile({"dev", "test"})
public class InMemoryTokenBlacklistGateway implements TokenBlacklistGateway {
    private final Set<String> blacklist = ConcurrentHashMap.newKeySet();
    // ...
}

// Prod/Demo: Redis blacklist
@Component
@Profile({"prod", "demo"})
@RequiredArgsConstructor
public class RedisTokenBlacklistGateway implements TokenBlacklistGateway {
    private final StringRedisTemplate redis;
    // ...
}
```

```java
// Dev/Test: Classpath keys
@Component
@Profile({"dev", "test"})
public class ClasspathRsaKeyProvider implements RsaKeyProvider {
    // Load from classpath:keys/
}

// Prod: Keystore keys
@Component
@Profile("prod")
public class KeystoreRsaKeyProvider implements RsaKeyProvider {
    // Load from filesystem keystore
}
```

```java
// Test: Controllable clock for time-dependent tests
@Component
@Profile("test")
public class TestClockProvider implements ClockProvider {
    private Instant fixedInstant = Instant.now();
    
    public void setFixedInstant(Instant instant) {
        this.fixedInstant = instant;
    }
    
    @Override
    public Instant now() {
        return fixedInstant;
    }
}

// Dev/Prod: System clock
@Component
@Profile({"dev", "prod"})
public class SystemClockProvider implements ClockProvider {
    @Override
    public Instant now() {
        return Instant.now();
    }
}
```

### Activating Profiles

**Local development** (default):
```bash
# No need to specify, dev is default
mvn spring-boot:run
```

**Explicit profile**:
```bash
mvn spring-boot:run -Dspring-boot.run.profiles=demo
```

**Environment variable**:
```bash
export SPRING_PROFILES_ACTIVE=prod
java -jar app.jar
```

**Docker**:
```bash
docker run -e SPRING_PROFILES_ACTIVE=prod spring-security-template:latest
```

**Kubernetes**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: app-config
data:
  SPRING_PROFILES_ACTIVE: "prod"
```

### Validation (Fail-Fast on Misconfiguration)

```java
@Component
public class ProfileValidator implements ApplicationListener<ApplicationReadyEvent> {
    
    @Value("${spring.profiles.active}")
    private String activeProfiles;
    
    @Override
    public void onApplicationEvent(ApplicationReadyEvent event) {
        if (activeProfiles.contains("prod") && activeProfiles.contains("dev")) {
            throw new IllegalStateException(
                "Cannot activate both 'prod' and 'dev' profiles simultaneously"
            );
        }
        
        if (activeProfiles.contains("prod")) {
            validateProductionConfig();
        }
    }
    
    private void validateProductionConfig() {
        // Ensure no dev-only features are enabled in prod
        if (swaggerEnabled) {
            throw new IllegalStateException("Swagger must be disabled in production");
        }
        if (h2ConsoleEnabled) {
            throw new IllegalStateException("H2 console must be disabled in production");
        }
    }
}
```

## Testing Profile Selection

```java
@SpringBootTest
@ActiveProfiles("dev")
class DevProfileTest {
    @Autowired TokenBlacklistGateway blacklist;
    
    @Test
    void shouldUseInMemoryBlacklistInDev() {
        assertThat(blacklist).isInstanceOf(InMemoryTokenBlacklistGateway.class);
    }
}

@SpringBootTest
@ActiveProfiles("prod")
class ProdProfileTest {
    @Autowired TokenBlacklistGateway blacklist;
    
    @Test
    void shouldUseRedisBlacklistInProd() {
        assertThat(blacklist).isInstanceOf(RedisTokenBlacklistGateway.class);
    }
}
```

## Profile Decision Matrix

| Feature | dev | test | demo | prod |
|---------|-----|------|------|------|
| Database | H2 (in-memory) | H2 (in-memory) | PostgreSQL | PostgreSQL/MySQL |
| JWT Keys | Classpath PEM | Classpath PEM | Embedded Keystore | External Keystore |
| Blacklist | In-memory | In-memory | Redis | Redis Cluster |
| Swagger UI | ✅ Enabled | ❌ Disabled | ✅ Enabled | ❌ Disabled |
| H2 Console | ✅ Enabled | ❌ Disabled | ❌ Disabled | ❌ Disabled |
| Rate Limiting | Relaxed (10/min) | Disabled | Moderate (10/min) | Strict (3/min) |
| Logging Level | DEBUG | WARN | INFO | WARN |
| Actuator Endpoints | All | health,info | health,info,metrics | health,prometheus |
| Session Timeout | 60 min | 5 min | 30 min | 15 min |

## References

- [Spring Boot - Profiles](https://docs.spring.io/spring-boot/docs/current/reference/html/features.html#features.profiles)
- [12-Factor App - Config](https://12factor.net/config)
- [Baeldung - Spring Profiles](https://www.baeldung.com/spring-profiles)

## Review

**Reviewers**: DevOps, Platform Team
**Approved by**: Technical Lead
**Review date**: 2025-12-26
