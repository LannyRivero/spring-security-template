# ADR-007: Redis for Token Blacklist and Session Registry

## Status

**Accepted**

**Date**: 2025-12-26

## Context

JWT-based stateless authentication requires mechanisms for:
- **Token revocation**: Blacklist tokens before natural expiration (logout, password change, security breach)
- **Concurrent session management**: Limit active sessions per user (prevent account sharing)
- **Performance**: Fast lookups (O(1) operations)
- **Scalability**: Support horizontal scaling (multiple app instances)
- **TTL automation**: Auto-expire entries (no manual cleanup)

In-memory solutions (e.g., `ConcurrentHashMap`) don't scale:
- ❌ State not shared across instances (logout on server A doesn't affect server B)
- ❌ Lost on restart (all revocations disappear)
- ❌ No TTL support (must implement manual cleanup)
- ❌ Memory leaks if not cleaned properly

We need a shared, distributed storage that:
- **Persists across restarts** (durability)
- **Scales horizontally** (works with load balancers)
- **Supports TTL natively** (auto-expiration)
- **Is fast** (sub-millisecond reads/writes)
- **Is operational-friendly** (mature, well-documented)

## Decision

We will use **Redis** for:
1. **Token Blacklist** (revoked JWTs)
2. **Session Registry** (concurrent session tracking)

### Redis Strategy

- **Development/Test**: In-memory adapters (no Redis dependency)
- **Demo/Production**: Redis (single instance or cluster)
- **Key design**: Namespaced keys with TTL matching token expiration
- **Data structures**: Strings for blacklist, Sorted Sets for session registry

### Blacklist eviction strategy

- **Blacklisted tokens rely exclusively on their natural expiration lifecycle.**
- **Each revoked token is stored with a TTL equal to its remaining lifetime**
- **Once expired, Redis automatically removes the entry**
- **No explicit cleanup jobs, schedulers, or key-scanning mechanisms are used**
- **This design avoids unsafe Redis operations and reduces operational complexity.**

### Architecture

```
application/auth/port/out/
├── TokenBlacklistGateway.java      # Interface
└── SessionRegistryGateway.java     # Interface

infrastructure/
└── security/
    ├── blacklist/
    │   └── InMemoryTokenBlacklistGateway.java   # @Profile({"dev", "test"})
    │   └── RedisTokenBlacklistGateway.java      # @Profile({"prod", "demo"})
    └── session/
        ├── InMemorySessionRegistryGateway.java  # @Profile({"dev", "test"})
        └── RedisSessionRegistryGateway.java      # @Profile({"prod", "demo"})
```

## Alternatives Considered

### Alternative 1: Database (JPA) for Blacklist

**Approach**: Store revoked tokens in PostgreSQL/MySQL.

**Pros**:
- ✅ No additional infrastructure (use existing database)
- ✅ ACID transactions
- ✅ Easy querying and auditing

**Cons**:
- ❌ **Slower**: Database lookups ~10-50ms vs Redis ~1ms
- ❌ **No native TTL**: Must implement scheduled cleanup jobs
- ❌ **Table bloat**: Expired tokens accumulate (requires maintenance)
- ❌ **Extra load**: Every API request queries database for blacklist check

**Why rejected**: **Performance**. Blacklist checks happen on **every authenticated request**. Database adds 10-50ms latency per request. Redis is orders of magnitude faster.

### Alternative 2: Hazelcast (Distributed Cache)

**Approach**: Use Hazelcast IMDG for distributed caching.

**Pros**:
- ✅ Embedded (no separate server required)
- ✅ Java-native
- ✅ TTL support

**Cons**:
- ⚠️ **Memory overhead**: Runs in-process (consumes app memory)
- ⚠️ **Operational complexity**: Cluster management, split-brain scenarios
- ⚠️ **Less mature tooling**: Compared to Redis (monitoring, backups)

**Why rejected**: Redis is **industry standard** with better tooling and operational maturity. Hazelcast is overkill for blacklist/session use case.

### Alternative 3: Apache Kafka (Event Sourcing)

**Approach**: Publish revocation events to Kafka, consume in all instances.

**Pros**:
- ✅ Event-driven, decoupled
- ✅ Audit trail (events are immutable)

**Cons**:
- ❌ **Overkill**: Kafka is for streaming, not key-value lookups
- ❌ **Complexity**: Requires Kafka cluster, consumer groups, offset management
- ❌ **Latency**: Event propagation delay (eventual consistency)
- ❌ **No built-in TTL**: Must implement expiration logic

**Why rejected**: **Over-engineering**. Kafka excels at event streaming, not real-time state queries.

### Alternative 4: Memcached

**Approach**: Use Memcached for distributed caching.

**Pros**:
- ✅ Simple, fast
- ✅ TTL support

**Cons**:
- ⚠️ **Limited data structures**: Only key-value (no Sets, Hashes, Sorted Sets)
- ⚠️ **No persistence**: Pure in-memory (lost on restart)
- ⚠️ **Less feature-rich**: Compared to Redis

**Why rejected**: Redis offers **more features** (data structures, persistence, pub/sub) at similar performance.

## Consequences

### Positive

- ✅ **Fast**: Sub-millisecond lookups (O(1) complexity)
- ✅ **Scalable**: Shared state across all application instances
- ✅ **Auto-expiration**: TTL eliminates need for cleanup jobs
- ✅ **Production-ready**: Redis is battle-tested (Twitter, GitHub, Stack Overflow)
- ✅ **Operational maturity**: Excellent monitoring (Redis Insights, Grafana dashboards)
- ✅ **Cloud-native**: Available as managed service (AWS ElastiCache, Azure Cache, GCP Memorystore)
- ✅ **Simple dev mode**: In-memory adapters for local development (no Redis required)

### Negative

- ⚠️ **External dependency**: Requires Redis server (ops overhead)
- ⚠️ **Network latency**: ~1-5ms for network calls (vs nanoseconds for in-memory)
- ⚠️ **Single point of failure**: If Redis goes down, revocations fail (mitigated by Redis Sentinel/Cluster)
- ⚠️ **Memory cost**: Redis instance adds to infrastructure cost

### Neutral

- ℹ️ Graceful degradation: If Redis unavailable, can fail-open (allow requests) or fail-closed (reject all)
- ℹ️ Redis persistence (RDB/AOF) provides durability if needed

## Implementation Notes

### Dependency

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

### Configuration

**Development** (`application-dev.yml`):
```yaml
# No Redis configuration (uses in-memory adapter)
```

**Production** (`application-prod.yml`):
```yaml
spring:
  data:
    redis:
      host: ${REDIS_HOST:localhost}
      port: ${REDIS_PORT:6379}
      password: ${REDIS_PASSWORD:}
      ssl:
        enabled: true
      timeout: 2000ms
      lettuce:
        pool:
          max-active: 8
          max-idle: 8
          min-idle: 2
```

**Redis Cluster** (`application-prod.yml`):
```yaml
spring:
  data:
    redis:
      cluster:
        nodes:
          - redis-node-1:6379
          - redis-node-2:6379
          - redis-node-3:6379
      password: ${REDIS_PASSWORD}
```

### Token Blacklist Implementation

**Outbound Port**:
```java
public interface TokenBlacklistGateway {
    void revoke(String jti, Instant expiresAt);
    boolean isRevoked(String jti);
}
```

**Redis Adapter**:
```java
@Component
@Profile({"prod", "demo"})
@RequiredArgsConstructor
public class RedisTokenBlacklistGateway implements TokenBlacklistGateway {
    
    private static final String PREFIX = "security:blacklist:jti:";
    private final StringRedisTemplate redis;
    private final ClockProvider clock;
    
    @Override
    public void revoke(String jti, Instant expiresAt) {
        if (jti == null || jti.isBlank() || expiresAt == null) {
            return;
        }
        
        long ttlSeconds = Duration.between(clock.now(), expiresAt).toSeconds();
        
        if (ttlSeconds <= 0) {
            return; // Already expired
        }
        
        redis.opsForValue().set(
            PREFIX + jti,
            "revoked",
            Duration.ofSeconds(ttlSeconds)
        );
    }
    
    @Override
    public boolean isRevoked(String jti) {
        if (jti == null || jti.isBlank()) {
            return false;
        }
        return Boolean.TRUE.equals(redis.hasKey(PREFIX + jti));
    }
}
```

**In-Memory Adapter** (dev/test):
```java
@Component
@Profile({"dev", "test"})
public class InMemoryTokenBlacklistGateway implements TokenBlacklistGateway {
    
    private final Map<String, Instant> blacklist = new ConcurrentHashMap<>();
    private final ClockProvider clock;
    
    @Override
    public void revoke(String jti, Instant expiresAt) {
        blacklist.put(jti, expiresAt);
    }
    
    @Override
    public boolean isRevoked(String jti) {
        Instant expiresAt = blacklist.get(jti);
        if (expiresAt == null) {
            return false;
        }
        if (clock.now().isAfter(expiresAt)) {
            blacklist.remove(jti); // Cleanup
            return false;
        }
        return true;
    }
}
```

### Session Registry Implementation

**Outbound Port**:
```java
public interface SessionRegistryGateway {
    void registerSession(String userId, String sessionId);
    void removeSession(String userId, String sessionId);
    Set<String> getActiveSessions(String userId);
    int getActiveSessionCount(String userId);
}
```

**Redis Adapter** (using Sets):
```java
@Component
@Profile({"prod", "demo"})
@RequiredArgsConstructor
public class RedisSessionRegistryGateway implements SessionRegistryGateway {
    
    private static final String PREFIX = "security:sessions:user:";
    private final StringRedisTemplate redis;
    
    @Override
    public void registerSession(String userId, String sessionId) {
        redis.opsForSet().add(PREFIX + userId, sessionId);
        redis.expire(PREFIX + userId, Duration.ofDays(30)); // Session TTL
    }
    
    @Override
    public void removeSession(String userId, String sessionId) {
        redis.opsForSet().remove(PREFIX + userId, sessionId);
    }
    
    @Override
    public Set<String> getActiveSessions(String userId) {
        return redis.opsForSet().members(PREFIX + userId);
    }
    
    @Override
    public int getActiveSessionCount(String userId) {
        Long count = redis.opsForSet().size(PREFIX + userId);
        return count != null ? count.intValue() : 0;
    }
}
```

### Usage in Use Case

```java
@Override
public JwtResult login(LoginCommand command) {
    User user = userGateway.findByUsername(command.username())
        .orElseThrow(InvalidCredentialsException::new);
    
    user.authenticate(command.password(), passwordHasher);
    
    // Check concurrent session limit
    int activeSessions = sessionRegistry.getActiveSessionCount(user.getId());
    if (activeSessions >= maxConcurrentSessions) {
        throw new MaxSessionsExceededException("Too many active sessions");
    }
    
    // Generate tokens
    String accessToken = tokenProvider.generateAccessToken(/* ... */);
    String refreshToken = tokenProvider.generateRefreshToken(/* ... */);
    
    // Register session
    JwtClaimsDTO refreshClaims = tokenProvider.parseToken(refreshToken);
    sessionRegistry.registerSession(user.getId(), refreshClaims.jti());
    
    return new JwtResult(accessToken, refreshToken, /* ... */);
}

@Override
public void logout(String refreshToken) {
    JwtClaimsDTO claims = tokenProvider.parseToken(refreshToken);
    
    // Revoke tokens
    tokenBlacklist.revoke(claims.jti(), claims.expiresAt());
    
    // Remove session
    sessionRegistry.removeSession(claims.subject(), claims.jti());
}
```

### Redis Key Design

| Use Case | Key Pattern | Value | TTL |
|----------|-------------|-------|-----|
| Blacklist (JTI) | `security:blacklist:jti:{jti}` | `"revoked"` | Token expiration time |
| Session Registry | `security:sessions:user:{userId}` | Set of `sessionId` | 30 days |
| Refresh Token | `security:refresh:{jti}` | JSON metadata | Refresh expiration time |

### Docker Compose (Local Development)

```yaml
services:
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
    command: redis-server --requirepass devpassword
    volumes:
      - redis-data:/data

volumes:
  redis-data:
```

### Health Check

```java
@Component
public class RedisHealthIndicator implements HealthIndicator {
    
    private final StringRedisTemplate redis;
    
    @Override
    public Health health() {
        try {
            redis.opsForValue().set("health:check", "ok", Duration.ofSeconds(5));
            String value = redis.opsForValue().get("health:check");
            
            if ("ok".equals(value)) {
                return Health.up().withDetail("redis", "connected").build();
            }
            return Health.down().withDetail("redis", "unexpected value").build();
            
        } catch (Exception e) {
            return Health.down().withException(e).build();
        }
    }
}
```

## Monitoring

### Metrics

```java
@Component
public class RedisMetrics {
    
    @Autowired
    public RedisMetrics(MeterRegistry registry, StringRedisTemplate redis) {
        Gauge.builder("redis.connections.active", redis, this::getActiveConnections)
            .register(registry);
        
        Gauge.builder("redis.keys.blacklist", redis, this::getBlacklistKeyCount)
            .register(registry);
    }
    
    private double getActiveConnections(StringRedisTemplate redis) {
        String info = redis.getConnectionFactory().getConnection().info("clients");
        // Parse connected_clients
        return parseConnectedClients(info);
    }
    
    private double getBlacklistKeyCount(StringRedisTemplate redis) {
        return redis.keys("security:blacklist:jti:*").size();
    }
}
```

### Alerts

```yaml
# Alert if Redis is down
- alert: RedisDown
  expr: up{job="redis"} == 0
  for: 1m
  annotations:
    summary: "Redis instance is down"

# Alert if blacklist keys accumulate (potential TTL issue)
- alert: BlacklistKeyAccumulation
  expr: redis_keys_blacklist > 10000
  annotations:
    summary: "Blacklist keys not expiring properly"
```

## Testing

```java
@SpringBootTest
@ActiveProfiles("prod")
@Testcontainers
class RedisTokenBlacklistGatewayTest {
    
    @Container
    static GenericContainer<?> redis = new GenericContainer<>("redis:7-alpine")
        .withExposedPorts(6379);
    
    @DynamicPropertySource
    static void redisProperties(DynamicPropertyRegistry registry) {
        registry.add("spring.data.redis.host", redis::getHost);
        registry.add("spring.data.redis.port", redis::getFirstMappedPort);
    }
    
    @Autowired TokenBlacklistGateway blacklist;
    
    @Test
    void shouldRevokeAndDetectRevokedToken() {
        String jti = "test-jti-123";
        Instant expiresAt = Instant.now().plusSeconds(3600);
        
        blacklist.revoke(jti, expiresAt);
        
        assertThat(blacklist.isRevoked(jti)).isTrue();
    }
    
    @Test
    void shouldAutoExpireAfterTTL() throws InterruptedException {
        String jti = "short-lived-jti";
        Instant expiresAt = Instant.now().plusSeconds(2);
        
        blacklist.revoke(jti, expiresAt);
        assertThat(blacklist.isRevoked(jti)).isTrue();
        
        Thread.sleep(3000);
        assertThat(blacklist.isRevoked(jti)).isFalse(); // Expired
    }
}
```

## References

- [Redis Documentation](https://redis.io/docs/)
- [Spring Data Redis](https://spring.io/projects/spring-data-redis)
- [Redis Best Practices](https://redis.io/docs/manual/patterns/)
- [AWS ElastiCache Best Practices](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/BestPractices.html)
- [Redis Sentinel - High Availability](https://redis.io/docs/manual/sentinel/)

## Review

**Reviewers**: DevOps, Backend Team, Infrastructure
**Approved by**: Technical Lead, Operations
**Review date**: 2025-12-26
