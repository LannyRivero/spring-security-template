# ADR-008: Stateless JWT Authentication over Session-Based

## Status

**Accepted**

**Date**: 2025-12-26

## Context

Modern web applications require authentication mechanisms that:
- **Scale horizontally**: Support multiple server instances without shared state
- **Enable microservices**: Authentication works across distributed services
- **Support mobile apps**: Native apps need token-based auth (no cookies)
- **Reduce server load**: Minimize database lookups on every request
- **Enable API gateways**: Tokens can be validated at gateway layer

Two primary authentication strategies exist:

### 1. Session-Based Authentication (Traditional)
- Server creates a session on login, stores session data (in-memory or database)
- Client receives a session ID (typically in a cookie)
- Every request includes the session ID
- Server looks up session data on each request

### 2. Stateless JWT Authentication
- Server issues a cryptographically signed JWT on login
- JWT contains all necessary claims (user ID, roles, expiration)
- Client includes JWT in `Authorization: Bearer` header
- Server validates JWT signature (no database lookup)

Challenges with session-based auth in distributed systems:
- ❌ **Sticky sessions required**: Load balancers must route user to same server
- ❌ **Shared session store**: Requires Redis/database for multi-instance deployments
- ❌ **Mobile incompatibility**: Native apps don't handle cookies well
- ❌ **Microservices complexity**: Each service needs access to session store
- ❌ **API gateway friction**: Gateway can't validate sessions without backend calls

## Decision

We will use **Stateless JWT-Based Authentication** as the primary mechanism.

### Configuration

```java
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) {
    http
        .sessionManagement(session -> session
            .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
        )
        .csrf(csrf -> csrf.disable()) // CSRF not needed for stateless APIs
        // ...
}
```

### Token Structure

**Access Token** (short-lived, 15-60 minutes):
```json
{
  "sub": "user-123",
  "iat": 1703635200,
  "exp": 1703638800,
  "jti": "access-abc-123",
  "iss": "spring-security-template",
  "roles": ["ROLE_USER"],
  "scopes": ["profile:read", "profile:write"]
}
```

**Refresh Token** (long-lived, 7-30 days):
```json
{
  "sub": "user-123",
  "iat": 1703635200,
  "exp": 1706227200,
  "jti": "refresh-xyz-456",
  "iss": "spring-security-template",
  "type": "refresh"
}
```

## Alternatives Considered

### Alternative 1: Session-Based with Redis

**Approach**: Store sessions in Redis, share across instances.

**Pros**:
- ✅ Server-side control (instant revocation)
- ✅ Smaller payloads (session ID is tiny)
- ✅ Sensitive data never exposed (stays server-side)

**Cons**:
- ❌ **Database dependency**: Redis must be up for auth to work
- ❌ **Performance**: Every request requires Redis lookup
- ❌ **Complexity**: Session replication, TTL management
- ❌ **Mobile unfriendly**: Cookies don't work well in native apps
- ❌ **Microservices friction**: Every service needs Redis access

**Why rejected**: While revocation is easier, the **operational complexity** and **performance overhead** make sessions less suitable for **microservices and mobile-first architectures**.

### Alternative 2: Hybrid (JWT + Session Registry)

**Approach**: Use JWTs for authentication, but track sessions in Redis for revocation.

**Pros**:
- ✅ Best of both worlds (stateless validation + revocation)
- ✅ Performance (validation is crypto-only, no DB lookup)
- ✅ Security (can revoke tokens via session registry)

**Cons**:
- ⚠️ **Complexity**: Requires both JWT logic and session tracking
- ⚠️ **Partial statefulness**: Still needs Redis for revocation

**Decision**: This is **our actual implementation** (see ADR-007). We use:
- **JWT for authentication** (stateless, fast)
- **Redis for revocation** (blacklist, session limits)

So technically, we're using a **stateless-first hybrid** approach.

### Alternative 3: OAuth2 with Authorization Server

**Approach**: Delegate authentication to a separate OAuth2 server (Keycloak, Auth0).

**Pros**:
- ✅ Mature, battle-tested
- ✅ Centralized identity management
- ✅ Supports SSO (Single Sign-On)
- ✅ OIDC compliance

**Cons**:
- ⚠️ **External dependency**: Another service to manage
- ⚠️ **Overkill**: For projects that don't need SSO or multi-app auth
- ⚠️ **Vendor lock-in**: (if using SaaS like Auth0)

**Why not primary**: This template is designed to be **self-contained**. OAuth2 integration is a future enhancement, not a requirement.

## Consequences

### Positive

- ✅ **Horizontal scalability**: No shared state between instances
- ✅ **Performance**: No database lookup on every request (only signature validation)
- ✅ **Microservices-ready**: Each service validates JWTs independently
- ✅ **Mobile-friendly**: Tokens work seamlessly with native apps (iOS, Android)
- ✅ **API gateway support**: Gateways can validate tokens without backend calls
- ✅ **Decoupling**: Auth logic is self-contained in JWT claims
- ✅ **Debugging**: Tokens can be inspected with jwt.io
- ✅ **CORS-friendly**: No cookie issues with cross-origin requests

### Negative

- ⚠️ **Revocation complexity**: Requires blacklist (Redis/database) for instant revocation
- ⚠️ **Token size**: JWTs are larger than session IDs (~500-1500 bytes)
- ⚠️ **Sensitive data exposure risk**: Claims are visible (base64, not encrypted)
- ⚠️ **Token theft**: If stolen, valid until expiration (mitigated by short TTL + refresh rotation)
- ⚠️ **Clock skew**: Expiration checks require synchronized clocks (use NTP)

### Neutral

- ℹ️ CSRF protection not needed (no cookies used)
- ℹ️ JWE (encryption) available if sensitive claims are required

## Implementation Notes

### Security Configuration

```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    
    @Bean
    public SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        JwtAuthorizationFilter jwtFilter
    ) throws Exception {
        
        http
            // Stateless session management
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // Disable CSRF (not needed for stateless APIs)
            .csrf(AbstractHttpConfigurer::disable)
            
            // CORS configuration
            .cors(Customizer.withDefaults())
            
            // JWT filter for token validation
            .addFilterBefore(
                jwtFilter,
                UsernamePasswordAuthenticationFilter.class
            )
            
            // Authorization rules
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/v1/auth/**").permitAll()
                .requestMatchers("/actuator/health").permitAll()
                .anyRequest().authenticated()
            )
            
            // Exception handlers
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(new CustomAuthenticationEntryPoint())
                .accessDeniedHandler(new CustomAccessDeniedHandler())
            );
        
        return http.build();
    }
}
```

### JWT Authorization Filter

```java
@Component
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    
    private final TokenProvider tokenProvider;
    private final TokenBlacklistGateway blacklist;
    
    @Override
    protected void doFilterInternal(
        HttpServletRequest request,
        HttpServletResponse response,
        FilterChain filterChain
    ) throws ServletException, IOException {
        
        String token = extractTokenFromHeader(request);
        
        if (token != null && tokenProvider.isValid(token)) {
            JwtClaimsDTO claims = tokenProvider.parseToken(token);
            
            // Check blacklist (for revocation)
            if (!blacklist.isRevoked(claims.jti())) {
                Authentication auth = createAuthentication(claims);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        
        filterChain.doFilter(request, response);
    }
    
    private String extractTokenFromHeader(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (header != null && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }
    
    private Authentication createAuthentication(JwtClaimsDTO claims) {
        Collection<GrantedAuthority> authorities = claims.scopes().stream()
            .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
            .collect(Collectors.toList());
        
        return new UsernamePasswordAuthenticationToken(
            claims.subject(),
            null,
            authorities
        );
    }
}
```

### Client Usage

**Login**:
```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username": "admin", "password": "password"}'

# Response:
{
  "accessToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expiresAt": "2025-12-26T15:30:00Z",
  "tokenType": "Bearer"
}
```

**Authenticated Request**:
```bash
curl -X GET http://localhost:8080/api/v1/secure/resource \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

**Refresh**:
```bash
curl -X POST http://localhost:8080/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refreshToken": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."}'
```

### Revocation (Logout)

```java
@Override
public void logout(String refreshToken) {
    JwtClaimsDTO claims = tokenProvider.parseToken(refreshToken);
    
    // Add to blacklist
    blacklist.revoke(claims.jti(), claims.expiresAt());
    
    // Publish audit event
    auditPublisher.publish(new UserLoggedOutEvent(claims.subject()));
}
```

### Best Practices

1. **Short-lived access tokens** (15-60 minutes)
2. **Long-lived refresh tokens** (7-30 days) with rotation
3. **HTTPS only** in production (prevent token interception)
4. **Blacklist for revocation** (Redis with TTL)
5. **Correlation-ID in logs** (track request flow)
6. **Rate limiting on auth endpoints** (prevent brute force)
7. **Token in Authorization header** (not URL params or body)

## Comparison Table

| Feature | Session-Based | Stateless JWT (This Template) |
|---------|---------------|-------------------------------|
| **Scalability** | ⚠️ Requires shared session store | ✅ No shared state |
| **Performance** | ⚠️ DB lookup per request | ✅ Crypto validation only |
| **Mobile Support** | ❌ Cookie issues | ✅ Native-friendly |
| **Microservices** | ⚠️ All services need session access | ✅ Independent validation |
| **Revocation** | ✅ Instant (delete session) | ⚠️ Requires blacklist |
| **Token Size** | ✅ Tiny (session ID) | ⚠️ Larger (~500-1500 bytes) |
| **Sensitive Data** | ✅ Server-side (hidden) | ⚠️ Visible (use JWE if needed) |
| **CSRF Protection** | ⚠️ Required | ✅ Not needed |
| **Debugging** | ⚠️ Opaque session ID | ✅ Human-readable claims |

## Monitoring

### Metrics

```java
Counter.builder("auth.jwt.validated").register(registry);
Counter.builder("auth.jwt.invalid").register(registry);
Counter.builder("auth.jwt.blacklisted").register(registry);

Timer.builder("auth.jwt.validation.time").register(registry);
```

### Alerts

```yaml
- alert: HighInvalidJwtRate
  expr: rate(auth_jwt_invalid[5m]) > 100
  annotations:
    summary: "High rate of invalid JWT validations"
```

## Testing

```java
@SpringBootTest
@AutoConfigureMockMvc
class JwtAuthenticationIntegrationTest {
    
    @Autowired MockMvc mockMvc;
    @Autowired TokenProvider tokenProvider;
    
    @Test
    void shouldAccessSecureEndpointWithValidToken() throws Exception {
        String token = tokenProvider.generateAccessToken(
            "user-123",
            List.of("ROLE_USER"),
            List.of("profile:read"),
            Duration.ofMinutes(15)
        );
        
        mockMvc.perform(get("/api/v1/secure/resource")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }
    
    @Test
    void shouldRejectRequestWithoutToken() throws Exception {
        mockMvc.perform(get("/api/v1/secure/resource"))
            .andExpect(status().isUnauthorized());
    }
    
    @Test
    void shouldRejectExpiredToken() throws Exception {
        // Token expired 1 hour ago
        String expiredToken = tokenProvider.generateAccessToken(
            "user-123",
            List.of("ROLE_USER"),
            List.of("profile:read"),
            Duration.ofHours(-1)
        );
        
        mockMvc.perform(get("/api/v1/secure/resource")
                .header("Authorization", "Bearer " + expiredToken))
            .andExpect(status().isUnauthorized());
    }
}
```

## References

- [RFC 7519 - JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Spring Security - OAuth2 Resource Server](https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/jwt.html)
- [Auth0 - JWT Introduction](https://jwt.io/introduction)
- [OWASP ASVS - Session Management](https://owasp.org/www-project-application-security-verification-standard/)

## Review

**Reviewers**: Security Team, Backend Chapter, Mobile Team
**Approved by**: Chief Architect, CISO
**Review date**: 2025-12-26
