# 🔐 RBAC + ABAC Authorization Matrix

This document defines the complete authorization model for the Spring Security Template, mapping **Roles** to **Scopes** to **Endpoints**.

---

## 📚 Table of Contents

1. [Authorization Model Overview](#authorization-model-overview)
2. [Role Definitions](#role-definitions)
3. [Scope Catalog](#scope-catalog)
4. [Authorization Matrix](#authorization-matrix)
5. [Endpoint Protection](#endpoint-protection)
6. [Implementation Guide](#implementation-guide)
7. [Testing Authorization](#testing-authorization)
8. [Extending the Model](#extending-the-model)

---

## Authorization Model Overview

### RBAC (Role-Based Access Control)

**Roles** are coarse-grained permissions assigned to users:
- `ROLE_ADMIN` - System administrators with full access
- `ROLE_USER` - Standard authenticated users
- `ROLE_AUDITOR` - Read-only access for compliance (future)
- `ROLE_SYSTEM` - Service-to-service communication (future)

### ABAC (Attribute-Based Access Control)

**Scopes** are fine-grained permissions in the format `resource:action`:
- **Resource**: The entity being accessed (e.g., `profile`, `user`, `simulation`)
- **Action**: The operation being performed (e.g., `read`, `write`, `delete`, `manage`)

**Example scopes**:
- `profile:read` - View own profile
- `profile:write` - Update own profile
- `user:manage` - Full user administration
- `simulation:read` - View simulations
- `simulation:write` - Create/update simulations

### Hybrid Model (RBAC + ABAC)

This template uses a **hybrid approach**:
1. **Roles** group users by responsibility
2. **Roles** grant **Scopes** automatically
3. **Endpoints** are protected by **Scopes** (not roles directly)

**Benefits**:
- ✅ Fine-grained control (ABAC)
- ✅ Easy management (RBAC)
- ✅ Scalable (add scopes without changing roles)
- ✅ Testable (scope-based assertions)

---

## Role Definitions

### ROLE_ADMIN

**Purpose**: System administrators with elevated privileges.

**Granted Scopes**:
- `profile:read` - View own profile
- `profile:write` - Update own profile
- `user:read` - View all users
- `user:write` - Create/update users
- `user:delete` - Delete users
- `user:manage` - Full user management (includes all user:* scopes)
- `audit:read` - View audit logs
- `system:config` - Modify system configuration

**Use Cases**:
- IT administrators
- Security officers
- System configurators

**Security Level**: 🔴 **High** - Full system access

---

### ROLE_USER

**Purpose**: Standard authenticated users with limited access.

**Granted Scopes**:
- `profile:read` - View own profile
- `profile:write` - Update own profile

**Use Cases**:
- End users
- Customers
- Standard employees

**Security Level**: 🟢 **Standard** - Self-service only

---

### ROLE_AUDITOR (Future)

**Purpose**: Compliance and security auditors with read-only access.

**Granted Scopes**:
- `audit:read` - View audit logs
- `user:read` - View user list (read-only)
- `security:report` - Generate security reports

**Use Cases**:
- Compliance officers
- Security auditors
- External reviewers

**Security Level**: 🟡 **Medium** - Read-only sensitive data

---

### ROLE_SYSTEM (Future)

**Purpose**: Service-to-service authentication for microservices.

**Granted Scopes**:
- `api:internal` - Internal API access
- `event:publish` - Publish domain events
- `metrics:write` - Write metrics data

**Use Cases**:
- Microservice communication
- Background jobs
- Integration services

**Security Level**: 🟠 **Service** - Machine-to-machine

---

## Scope Catalog

### Profile Scopes (Self-Service)

| Scope | Action | Resource | Description |
|-------|--------|----------|-------------|
| `profile:read` | Read | Profile | View own user profile |
| `profile:write` | Write | Profile | Update own profile (name, email, etc.) |
| `profile:delete` | Delete | Profile | Delete own account (self-deletion) |

---

### User Management Scopes (Administration)

| Scope | Action | Resource | Description |
|-------|--------|----------|-------------|
| `user:read` | Read | User | List and view all users |
| `user:write` | Write | User | Create and update user accounts |
| `user:delete` | Delete | User | Permanently delete users |
| `user:manage` | Manage | User | Full user administration (all user:* scopes) |
| `user:impersonate` | Impersonate | User | Assume another user's identity (support) |

---

### Audit Scopes (Compliance)

| Scope | Action | Resource | Description |
|-------|--------|----------|-------------|
| `audit:read` | Read | Audit | View audit logs and security events |
| `audit:export` | Export | Audit | Export audit logs (CSV, JSON) |

---

### System Scopes (Configuration)

| Scope | Action | Resource | Description |
|-------|--------|----------|-------------|
| `system:config` | Config | System | Modify system-level configuration |
| `system:health` | Health | System | View system health and diagnostics |
| `system:restart` | Restart | System | Restart application or services |

---

### Example Domain Scopes (Extensible)

These are **examples** for custom domains. Replace with your application's entities:

| Scope | Action | Resource | Description |
|-------|--------|----------|-------------|
| `simulation:read` | Read | Simulation | View simulations |
| `simulation:write` | Write | Simulation | Create/update simulations |
| `simulation:execute` | Execute | Simulation | Run simulations |
| `simulation:delete` | Delete | Simulation | Delete simulations |
| `document:read` | Read | Document | View documents |
| `document:write` | Write | Document | Upload/modify documents |
| `report:generate` | Generate | Report | Generate reports |

---

## Authorization Matrix

### Complete Role → Scope Mapping

| Scope | ROLE_ADMIN | ROLE_USER | ROLE_AUDITOR | ROLE_SYSTEM |
|-------|------------|-----------|--------------|-------------|
| **Profile** | | | | |
| `profile:read` | ✅ | ✅ | ❌ | ❌ |
| `profile:write` | ✅ | ✅ | ❌ | ❌ |
| `profile:delete` | ✅ | ✅ | ❌ | ❌ |
| **User Management** | | | | |
| `user:read` | ✅ | ❌ | ✅ (read-only) | ❌ |
| `user:write` | ✅ | ❌ | ❌ | ❌ |
| `user:delete` | ✅ | ❌ | ❌ | ❌ |
| `user:manage` | ✅ | ❌ | ❌ | ❌ |
| `user:impersonate` | ✅ | ❌ | ❌ | ❌ |
| **Audit** | | | | |
| `audit:read` | ✅ | ❌ | ✅ | ❌ |
| `audit:export` | ✅ | ❌ | ✅ | ❌ |
| **System** | | | | |
| `system:config` | ✅ | ❌ | ❌ | ❌ |
| `system:health` | ✅ | ❌ | ❌ | ✅ |
| `system:restart` | ✅ | ❌ | ❌ | ❌ |
| **API (Service-to-Service)** | | | | |
| `api:internal` | ❌ | ❌ | ❌ | ✅ |
| `event:publish` | ❌ | ❌ | ❌ | ✅ |

---

## Endpoint Protection

### Mapping Endpoints to Scopes

| Endpoint | Method | Scope Required | Description |
|----------|--------|----------------|-------------|
| **Authentication** (Public) | | | |
| `/api/v1/auth/login` | POST | _none_ | User login |
| `/api/v1/auth/refresh` | POST | _none_ | Refresh access token |
| `/api/v1/auth/register` | POST | _none_ (dev only) | Register new account |
| **Profile** (Self-Service) | | | |
| `/api/v1/auth/me` | GET | `profile:read` | Get current user profile |
| `/api/v1/profile` | GET | `profile:read` | View own profile |
| `/api/v1/profile` | PUT | `profile:write` | Update own profile |
| `/api/v1/profile` | DELETE | `profile:delete` | Delete own account |
| `/api/v1/profile/password` | POST | `profile:write` | Change password |
| **User Management** (Admin) | | | |
| `/api/v1/users` | GET | `user:read` OR `user:manage` | List all users |
| `/api/v1/users/{id}` | GET | `user:read` OR `user:manage` | Get user by ID |
| `/api/v1/users` | POST | `user:write` OR `user:manage` | Create new user |
| `/api/v1/users/{id}` | PUT | `user:write` OR `user:manage` | Update user |
| `/api/v1/users/{id}` | DELETE | `user:delete` OR `user:manage` | Delete user |
| `/api/v1/users/{id}/roles` | PUT | `user:manage` | Assign roles to user |
| **Audit** (Compliance) | | | |
| `/api/v1/audit/events` | GET | `audit:read` | View audit logs |
| `/api/v1/audit/events/export` | GET | `audit:export` | Export audit logs |
| **System** (Admin Only) | | | |
| `/api/v1/system/config` | GET | `system:config` | View system config |
| `/api/v1/system/config` | PUT | `system:config` | Update system config |
| `/actuator/health` | GET | _none_ | Health check (public) |
| `/actuator/prometheus` | GET | `system:health` | Prometheus metrics |

---

## Implementation Guide

### 1. Database Seeding (Flyway Migrations)

**Create Scopes** (`V3__seed_scopes.sql`):
```sql
INSERT INTO scopes (id, name) VALUES
-- Profile scopes
(UUID(), 'profile:read'),
(UUID(), 'profile:write'),
(UUID(), 'profile:delete'),

-- User management scopes
(UUID(), 'user:read'),
(UUID(), 'user:write'),
(UUID(), 'user:delete'),
(UUID(), 'user:manage'),

-- Audit scopes
(UUID(), 'audit:read'),
(UUID(), 'audit:export'),

-- System scopes
(UUID(), 'system:config'),
(UUID(), 'system:health');
```

**Assign Scopes to Roles** (`V4__seed_role_scope_relations.sql`):
```sql
-- ROLE_ADMIN gets all scopes
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r, scopes s
WHERE r.name = 'ROLE_ADMIN' 
  AND s.name IN (
    'profile:read', 'profile:write', 'profile:delete',
    'user:read', 'user:write', 'user:delete', 'user:manage',
    'audit:read', 'audit:export',
    'system:config', 'system:health'
  );

-- ROLE_USER gets basic profile scopes
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r, scopes s
WHERE r.name = 'ROLE_USER' 
  AND s.name IN ('profile:read', 'profile:write');
```

---

### 2. Controller Protection with @PreAuthorize

**Method-Level Security**:

```java
@RestController
@RequestMapping("/api/v1/profile")
@RequiredArgsConstructor
public class ProfileController {
    
    private final ProfileService profileService;
    
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_profile:read')")
    public ResponseEntity<ProfileResponse> getProfile(
        @AuthenticationPrincipal String userId
    ) {
        ProfileResult result = profileService.getProfile(userId);
        return ResponseEntity.ok(toResponse(result));
    }
    
    @PutMapping
    @PreAuthorize("hasAuthority('SCOPE_profile:write')")
    public ResponseEntity<ProfileResponse> updateProfile(
        @AuthenticationPrincipal String userId,
        @Valid @RequestBody UpdateProfileRequest request
    ) {
        ProfileResult result = profileService.updateProfile(userId, request);
        return ResponseEntity.ok(toResponse(result));
    }
    
    @DeleteMapping
    @PreAuthorize("hasAuthority('SCOPE_profile:delete')")
    public ResponseEntity<Void> deleteProfile(
        @AuthenticationPrincipal String userId
    ) {
        profileService.deleteProfile(userId);
        return ResponseEntity.noContent().build();
    }
}
```

**Admin-Only Endpoints**:

```java
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserManagementController {
    
    private final UserManagementService userService;
    
    @GetMapping
    @PreAuthorize("hasAnyAuthority('SCOPE_user:read', 'SCOPE_user:manage')")
    public ResponseEntity<Page<UserResponse>> listUsers(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "20") int size
    ) {
        PageResult<User> users = userService.listUsers(page, size);
        return ResponseEntity.ok(toPageResponse(users));
    }
    
    @PostMapping
    @PreAuthorize("hasAnyAuthority('SCOPE_user:write', 'SCOPE_user:manage')")
    public ResponseEntity<UserResponse> createUser(
        @Valid @RequestBody CreateUserRequest request
    ) {
        UserResult result = userService.createUser(request);
        return ResponseEntity.status(HttpStatus.CREATED).body(toResponse(result));
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAnyAuthority('SCOPE_user:delete', 'SCOPE_user:manage')")
    public ResponseEntity<Void> deleteUser(@PathVariable String id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }
}
```

**Complex Authorization (OR/AND Logic)**:

```java
// Multiple scopes (OR logic)
@PreAuthorize("hasAnyAuthority('SCOPE_user:write', 'SCOPE_user:manage')")

// Multiple scopes (AND logic)
@PreAuthorize("hasAuthority('SCOPE_user:read') and hasAuthority('SCOPE_audit:read')")

// Role + Scope combination
@PreAuthorize("hasRole('ADMIN') or hasAuthority('SCOPE_user:manage')")

// Custom SpEL expressions
@PreAuthorize("@authorizationService.canAccessUser(#userId, authentication)")
```

---

### 3. JWT Token Claims

Access tokens include both **roles** and **scopes**:

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

**Token Generation** (`NimbusJwtTokenProvider`):
```java
JWTClaimsSet claims = new JWTClaimsSet.Builder()
    .subject(userId)
    .issueTime(Date.from(issuedAt))
    .expirationTime(Date.from(expiresAt))
    .jwtID(jti)
    .issuer("spring-security-template")
    .claim("roles", roles)        // ["ROLE_USER"]
    .claim("scopes", scopes)      // ["profile:read", "profile:write"]
    .build();
```

---

### 4. Spring Security Configuration

**Enable Method Security**:
```java
@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)  // ⚠️ Required for @PreAuthorize
public class SecurityConfig {
    // ...
}
```

**Convert Scopes to Authorities** (`JwtAuthorizationFilter`):
```java
private Authentication createAuthentication(JwtClaimsDTO claims) {
    Collection<GrantedAuthority> authorities = new ArrayList<>();
    
    // Add roles
    claims.roles().forEach(role -> 
        authorities.add(new SimpleGrantedAuthority(role))
    );
    
    // Add scopes (prefixed with "SCOPE_")
    claims.scopes().forEach(scope -> 
        authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope))
    );
    
    return new UsernamePasswordAuthenticationToken(
        claims.subject(),
        null,
        authorities
    );
}
```

---

## Testing Authorization

### Unit Tests (Method Security)

```java
@SpringBootTest
@AutoConfigureMockMvc
class ProfileControllerAuthorizationTest {
    
    @Autowired MockMvc mockMvc;
    @Autowired TokenProvider tokenProvider;
    
    @Test
    void shouldAllowAccessWithProfileReadScope() throws Exception {
        String token = tokenProvider.generateAccessToken(
            "user-123",
            List.of("ROLE_USER"),
            List.of("profile:read"),  // ✅ Has required scope
            Duration.ofMinutes(15)
        );
        
        mockMvc.perform(get("/api/v1/profile")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }
    
    @Test
    void shouldDenyAccessWithoutProfileReadScope() throws Exception {
        String token = tokenProvider.generateAccessToken(
            "user-123",
            List.of("ROLE_USER"),
            List.of(), // ❌ No scopes
            Duration.ofMinutes(15)
        );
        
        mockMvc.perform(get("/api/v1/profile")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }
    
    @Test
    void shouldDenyUserFromAccessingAdminEndpoint() throws Exception {
        String token = tokenProvider.generateAccessToken(
            "user-123",
            List.of("ROLE_USER"),
            List.of("profile:read", "profile:write"),
            Duration.ofMinutes(15)
        );
        
        mockMvc.perform(get("/api/v1/users")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden()); // ❌ Needs user:read or user:manage
    }
    
    @Test
    void shouldAllowAdminToAccessUserManagement() throws Exception {
        String token = tokenProvider.generateAccessToken(
            "admin-123",
            List.of("ROLE_ADMIN"),
            List.of("user:read", "user:write", "user:manage"),
            Duration.ofMinutes(15)
        );
        
        mockMvc.perform(get("/api/v1/users")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }
}
```

### Integration Tests (Full Flow)

```java
@SpringBootTest
@Transactional
class AuthorizationIntegrationTest {
    
    @Autowired AuthUseCase authUseCase;
    @Autowired UserManagementService userService;
    
    @Test
    void userCanOnlyAccessOwnProfile() {
        // Given: User logs in
        JwtResult tokens = authUseCase.login(
            new LoginCommand("user@example.com", "password")
        );
        
        // When: User accesses their own profile (allowed)
        MeResult profile = authUseCase.me(new MeQuery(tokens.accessToken()));
        assertThat(profile).isNotNull();
        
        // Then: User cannot access admin endpoints
        assertThatThrownBy(() -> 
            userService.listUsers(0, 20)
        ).isInstanceOf(AccessDeniedException.class);
    }
    
    @Test
    void adminCanAccessAllEndpoints() {
        // Given: Admin logs in
        JwtResult tokens = authUseCase.login(
            new LoginCommand("admin@example.com", "password")
        );
        
        // Then: Admin can access user management
        PageResult<User> users = userService.listUsers(0, 20);
        assertThat(users).isNotNull();
        
        // And: Admin can access their own profile
        MeResult profile = authUseCase.me(new MeQuery(tokens.accessToken()));
        assertThat(profile).isNotNull();
    }
}
```

---

## Extending the Model

### Adding a New Scope

**1. Define the Scope** (Flyway migration):
```sql
-- V10__add_simulation_scopes.sql
INSERT INTO scopes (id, name) VALUES
(UUID(), 'simulation:read'),
(UUID(), 'simulation:write'),
(UUID(), 'simulation:execute'),
(UUID(), 'simulation:delete');
```

**2. Assign to Roles**:
```sql
-- V11__assign_simulation_scopes.sql
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r, scopes s
WHERE r.name = 'ROLE_ADMIN' 
  AND s.name IN ('simulation:read', 'simulation:write', 'simulation:execute', 'simulation:delete');

INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r, scopes s
WHERE r.name = 'ROLE_USER' 
  AND s.name = 'simulation:read'; -- Users can only read
```

**3. Protect Endpoints**:
```java
@RestController
@RequestMapping("/api/v1/simulations")
public class SimulationController {
    
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_simulation:read')")
    public ResponseEntity<List<SimulationResponse>> list() {
        // ...
    }
    
    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_simulation:write')")
    public ResponseEntity<SimulationResponse> create(@RequestBody CreateSimulationRequest request) {
        // ...
    }
    
    @PostMapping("/{id}/execute")
    @PreAuthorize("hasAuthority('SCOPE_simulation:execute')")
    public ResponseEntity<ExecutionResult> execute(@PathVariable String id) {
        // ...
    }
    
    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_simulation:delete')")
    public ResponseEntity<Void> delete(@PathVariable String id) {
        // ...
    }
}
```

**4. Update This Matrix**:
- Add new scopes to [Scope Catalog](#scope-catalog)
- Update [Authorization Matrix](#authorization-matrix)
- Document in [Endpoint Protection](#endpoint-protection)

---

### Adding a New Role

**1. Create Role** (Flyway migration):
```sql
-- V12__add_analyst_role.sql
INSERT INTO roles (id, name) VALUES
(UUID(), 'ROLE_ANALYST');
```

**2. Assign Scopes**:
```sql
-- V13__assign_analyst_scopes.sql
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r, scopes s
WHERE r.name = 'ROLE_ANALYST' 
  AND s.name IN (
    'simulation:read',
    'simulation:execute',
    'report:generate',
    'audit:read'
  );
```

**3. Document**:
- Add to [Role Definitions](#role-definitions)
- Update [Authorization Matrix](#authorization-matrix)

---

## Best Practices

### ✅ DO

- **Use scopes for endpoint protection**, not roles directly
- **Prefix scopes with "SCOPE_"** in `@PreAuthorize`
- **Name scopes with `resource:action` format**
- **Test authorization in unit and integration tests**
- **Document new scopes in this matrix**
- **Use `hasAnyAuthority()` for OR logic**
- **Use `and` for AND logic in SpEL expressions**

### ❌ DON'T

- **Don't hardcode roles in business logic** (use scopes)
- **Don't use `@Secured` or `@RolesAllowed`** (use `@PreAuthorize`)
- **Don't mix role-based and scope-based checks** (choose scopes)
- **Don't expose internal role structure in APIs** (use scopes in responses)
- **Don't forget to test negative cases** (missing scopes)

---

## References

- [ADR-003: Hexagonal Architecture](../adr/003-hexagonal-architecture.md) - Authorization policy in domain layer
- [ADR-004: Refresh Token Strategy](../adr/004-refresh-token-strategy.md) - Token claims structure
- [Spring Security - Method Security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [OWASP ASVS - Access Control](https://owasp.org/www-project-application-security-verification-standard/)
- [RFC 9068 - JWT Profile for OAuth 2.0 Access Tokens](https://datatracker.ietf.org/doc/html/rfc9068)

---

**Last Updated**: 2025-12-26  
**Version**: 1.0  
**Maintainer**: Security Team
