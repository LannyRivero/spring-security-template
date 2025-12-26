# 🛡️ Scope Implementation Guide

Step-by-step guide to implementing scope-based authorization in Spring Security with **@PreAuthorize**.

---

## Table of Contents

1. [Configuration](#configuration)
2. [Controller Protection](#controller-protection)
3. [Service Layer Protection](#service-layer-protection)
4. [Method-Level Security](#method-level-security)
5. [Custom Security Expressions](#custom-security-expressions)
6. [Testing Authorization](#testing-authorization)
7. [Common Pitfalls](#common-pitfalls)
8. [Best Practices](#best-practices)

---

## Configuration

### 1. Enable Method Security

Already configured in your template:

```java
@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {
    // JWT filter chain, authentication manager, etc.
}
```

**Key Points**:
- `@EnableMethodSecurity` replaces deprecated `@EnableGlobalMethodSecurity`
- `prePostEnabled = true` enables `@PreAuthorize`, `@PostAuthorize`
- Works with Spring Security 6.x+

---

### 2. JWT Token Structure

Your `TokenProvider` already includes scopes in JWT claims:

```java
public String generateAccessToken(
    String username,
    List<String> roles,
    List<String> scopes,
    Duration validity
) {
    // Claims include:
    // - "roles": ["ROLE_ADMIN"]
    // - "scopes": ["user:read", "user:write"]
}
```

**Token Payload Example**:
```json
{
  "sub": "john.doe",
  "roles": ["ROLE_ADMIN"],
  "scopes": ["profile:read", "profile:write", "user:read", "user:manage"],
  "iat": 1703577600,
  "exp": 1703578500
}
```

---

### 3. Authority Mapping

Your `JwtAuthenticationConverter` maps scopes to `GrantedAuthority`:

```java
private Collection<GrantedAuthority> extractAuthorities(Jwt jwt) {
    List<String> scopes = jwt.getClaimAsStringList("scopes");
    
    return scopes.stream()
        .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
        .collect(Collectors.toList());
}
```

**Result**: `user:read` → `SCOPE_user:read` (Spring Security convention)

---

## Controller Protection

### Basic Pattern

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_user:read')")
    public List<UserDto> getAllUsers() {
        return userService.findAll();
    }

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_user:write')")
    public UserDto createUser(@RequestBody CreateUserRequest request) {
        return userService.create(request);
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasAuthority('SCOPE_user:delete')")
    public void deleteUser(@PathVariable String id) {
        userService.delete(id);
    }
}
```

**Key Points**:
- Use `SCOPE_` prefix (Spring Security convention)
- Exact scope name from JWT token
- 403 Forbidden if user lacks scope

---

### Multiple Scopes (OR Logic)

Allow access if user has **any** of the listed scopes:

```java
@GetMapping("/{id}")
@PreAuthorize("hasAnyAuthority('SCOPE_user:read', 'SCOPE_user:manage')")
public UserDto getUser(@PathVariable String id) {
    return userService.findById(id);
}
```

**Explanation**:
- `hasAnyAuthority(scope1, scope2, ...)` → OR condition
- User needs **at least one** scope
- Useful for read-only vs. admin scenarios

---

### Multiple Scopes (AND Logic)

Require **all** scopes:

```java
@PostMapping("/{id}/promote-to-admin")
@PreAuthorize("hasAuthority('SCOPE_user:write') AND hasAuthority('SCOPE_role:manage')")
public void promoteToAdmin(@PathVariable String id) {
    userService.grantRole(id, "ROLE_ADMIN");
}
```

**Explanation**:
- `AND` operator for multiple conditions
- User must have **both** `user:write` and `role:manage`
- Use for sensitive operations requiring multiple permissions

---

### Combining Roles and Scopes

Check both role and scope:

```java
@PostMapping("/admin/reset-password")
@PreAuthorize("hasRole('ADMIN') AND hasAuthority('SCOPE_user:manage')")
public void resetUserPassword(@RequestBody ResetPasswordRequest request) {
    userService.resetPassword(request.getUserId(), request.getNewPassword());
}
```

**When to use**:
- Extra layer of security
- Compliance requirements (e.g., "only admins with explicit scope")
- Legacy systems migrating from role-based to scope-based

---

### Path Variable Authorization

Restrict access based on path parameters:

```java
@GetMapping("/profile/{username}")
@PreAuthorize("hasAuthority('SCOPE_profile:read') AND (#username == authentication.name OR hasAuthority('SCOPE_user:manage'))")
public ProfileDto getProfile(@PathVariable String username) {
    return profileService.findByUsername(username);
}
```

**Explanation**:
- `#username` → method parameter
- `authentication.name` → current user's username
- Users can access their own profile OR admins with `user:manage` can access any profile

---

### Request Body Authorization

Check fields from request body:

```java
@PutMapping("/{id}")
@PreAuthorize("hasAuthority('SCOPE_user:write') AND (#request.id == #id)")
public UserDto updateUser(
    @PathVariable String id,
    @RequestBody UpdateUserRequest request
) {
    return userService.update(id, request);
}
```

**Warning**: ⚠️ Request body checks have limitations (Spring SpEL cannot deserialize complex objects easily). Prefer service-layer checks for complex logic.

---

## Service Layer Protection

### Why Protect Services?

Controllers can be bypassed:
- Internal method calls
- Scheduled jobs
- Event listeners
- Direct service injection

**Best Practice**: Protect both controller AND service layer.

---

### Service Method Protection

```java
@Service
@Validated
public class UserService {

    @PreAuthorize("hasAuthority('SCOPE_user:read')")
    public List<User> findAll() {
        return userRepository.findAll();
    }

    @PreAuthorize("hasAuthority('SCOPE_user:write')")
    public User create(CreateUserRequest request) {
        User user = User.create(request.getUsername(), request.getEmail());
        return userRepository.save(user);
    }

    @PreAuthorize("hasAuthority('SCOPE_user:delete')")
    public void delete(String userId) {
        userRepository.deleteById(userId);
    }

    @PreAuthorize("hasAuthority('SCOPE_user:impersonate')")
    public String generateImpersonationToken(String targetUserId) {
        // Sensitive operation - requires special scope
        return tokenProvider.generateImpersonationToken(targetUserId);
    }
}
```

**Benefits**:
- **Defense in depth**: Controllers + Services protected
- **Consistent enforcement**: All entry points secured
- **Clear intent**: Service method signature shows required permission

---

### Object-Level Authorization

Check ownership before allowing action:

```java
@Service
public class ProfileService {

    @PreAuthorize("hasAuthority('SCOPE_profile:write') AND @profileOwnershipChecker.isOwner(#profileId, authentication.name)")
    public void updateProfile(String profileId, UpdateProfileRequest request) {
        // Only profile owner can update
        Profile profile = profileRepository.findById(profileId)
            .orElseThrow(() -> new NotFoundException("Profile not found"));
        
        profile.update(request);
        profileRepository.save(profile);
    }
}
```

**Custom Checker Bean**:
```java
@Component("profileOwnershipChecker")
public class ProfileOwnershipChecker {
    
    @Autowired
    private ProfileRepository profileRepository;
    
    public boolean isOwner(String profileId, String username) {
        return profileRepository.findById(profileId)
            .map(profile -> profile.getOwnerUsername().equals(username))
            .orElse(false);
    }
}
```

---

## Method-Level Security

### @PostAuthorize (Filter Results)

Check authorization **after** method execution:

```java
@GetMapping("/profile")
@PostAuthorize("returnObject.username == authentication.name OR hasAuthority('SCOPE_user:manage')")
public ProfileDto getMyProfile() {
    String username = SecurityContextHolder.getContext().getAuthentication().getName();
    return profileService.findByUsername(username);
}
```

**Use Cases**:
- Verify returned object belongs to current user
- Filter results based on ownership
- Complex checks requiring method result

---

### @PreFilter (Filter Input)

Filter collection parameters **before** method execution:

```java
@PostMapping("/bulk-update")
@PreFilter("filterObject.ownerId == authentication.name OR hasAuthority('SCOPE_user:manage')")
public void bulkUpdateProfiles(@RequestBody List<ProfileUpdateDto> profiles) {
    // Only processes profiles owned by current user
    profileService.bulkUpdate(profiles);
}
```

**Limitation**: Only works with collections (`List`, `Set`, `Array`).

---

### @PostFilter (Filter Output)

Filter collection results **after** method execution:

```java
@GetMapping("/all")
@PostFilter("filterObject.visibility == 'PUBLIC' OR filterObject.ownerId == authentication.name")
public List<ProfileDto> getAllProfiles() {
    // Returns all profiles, but filters to only public ones + user's own
    return profileService.findAll();
}
```

**Performance Warning**: ⚠️ Method executes fully, then filters. Inefficient for large datasets. Prefer repository-level filtering.

---

## Custom Security Expressions

### Create Custom Expression Handler

```java
@Component("customSecurityExpressions")
public class CustomSecurityExpressions {
    
    @Autowired
    private UserRepository userRepository;
    
    @Autowired
    private RoleService roleService;
    
    /**
     * Check if current user can manage target user
     */
    public boolean canManageUser(String targetUserId, Authentication authentication) {
        String currentUsername = authentication.getName();
        
        // Users can manage themselves
        if (userRepository.findById(targetUserId)
                .map(User::getUsername)
                .filter(username -> username.equals(currentUsername))
                .isPresent()) {
            return true;
        }
        
        // Check if user has user:manage scope
        return authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("SCOPE_user:manage"));
    }
    
    /**
     * Check if user belongs to organization
     */
    public boolean belongsToOrganization(String orgId, Authentication authentication) {
        String username = authentication.getName();
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        
        return user.getOrganizations().stream()
            .anyMatch(org -> org.getId().equals(orgId));
    }
    
    /**
     * Check if user has specific scope for resource
     */
    public boolean hasScopeForResource(String resource, String action, Authentication authentication) {
        String requiredScope = resource + ":" + action;
        return authentication.getAuthorities().stream()
            .anyMatch(auth -> auth.getAuthority().equals("SCOPE_" + requiredScope));
    }
}
```

### Use Custom Expressions

```java
@RestController
@RequestMapping("/api/users")
public class UserController {
    
    @PutMapping("/{userId}")
    @PreAuthorize("@customSecurityExpressions.canManageUser(#userId, authentication)")
    public UserDto updateUser(
        @PathVariable String userId,
        @RequestBody UpdateUserRequest request
    ) {
        return userService.update(userId, request);
    }
    
    @GetMapping("/org/{orgId}/members")
    @PreAuthorize("@customSecurityExpressions.belongsToOrganization(#orgId, authentication)")
    public List<UserDto> getOrganizationMembers(@PathVariable String orgId) {
        return userService.findByOrganizationId(orgId);
    }
}
```

---

## Testing Authorization

### Unit Tests (MockMvc)

```java
@SpringBootTest
@AutoConfigureMockMvc
class UserControllerAuthorizationTest {
    
    @Autowired
    private MockMvc mockMvc;
    
    @Autowired
    private TokenProvider tokenProvider;
    
    @Test
    void shouldAllowAccessWithCorrectScope() throws Exception {
        String token = tokenProvider.generateAccessToken(
            "john.doe",
            List.of("ROLE_USER"),
            List.of("user:read"),
            Duration.ofMinutes(15)
        );
        
        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }
    
    @Test
    void shouldDenyAccessWithoutScope() throws Exception {
        String token = tokenProvider.generateAccessToken(
            "john.doe",
            List.of("ROLE_USER"),
            List.of("profile:read"),  // Wrong scope
            Duration.ofMinutes(15)
        );
        
        mockMvc.perform(get("/api/users")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }
    
    @Test
    void shouldDenyAccessWithoutToken() throws Exception {
        mockMvc.perform(get("/api/users"))
            .andExpect(status().isUnauthorized());
    }
}
```

---

### Service Layer Tests

```java
@SpringBootTest
class UserServiceAuthorizationTest {
    
    @Autowired
    private UserService userService;
    
    @Test
    @WithMockUser(username = "admin", authorities = {"SCOPE_user:read"})
    void shouldAllowFindAllWithScope() {
        List<User> users = userService.findAll();
        assertNotNull(users);
    }
    
    @Test
    @WithMockUser(username = "user", authorities = {"SCOPE_profile:read"})
    void shouldDenyFindAllWithoutScope() {
        assertThrows(AccessDeniedException.class, () -> userService.findAll());
    }
}
```

---

### Custom Authentication Builder

```java
public class TestAuthenticationBuilder {
    
    private String username = "test-user";
    private List<String> roles = List.of("ROLE_USER");
    private List<String> scopes = new ArrayList<>();
    
    public static TestAuthenticationBuilder aUser() {
        return new TestAuthenticationBuilder();
    }
    
    public TestAuthenticationBuilder withUsername(String username) {
        this.username = username;
        return this;
    }
    
    public TestAuthenticationBuilder withRoles(String... roles) {
        this.roles = Arrays.asList(roles);
        return this;
    }
    
    public TestAuthenticationBuilder withScopes(String... scopes) {
        this.scopes = Arrays.asList(scopes);
        return this;
    }
    
    public Authentication build() {
        List<GrantedAuthority> authorities = scopes.stream()
            .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
            .collect(Collectors.toList());
        
        return new UsernamePasswordAuthenticationToken(
            username,
            null,
            authorities
        );
    }
}

// Usage in tests
@Test
void testWithCustomAuth() {
    Authentication auth = TestAuthenticationBuilder.aUser()
        .withUsername("john.doe")
        .withScopes("user:read", "profile:write")
        .build();
    
    SecurityContextHolder.getContext().setAuthentication(auth);
    
    // Test method that requires scopes
    userService.findAll();
}
```

---

## Common Pitfalls

### ❌ Missing SCOPE_ Prefix

```java
// WRONG
@PreAuthorize("hasAuthority('user:read')")
public void method() { }

// CORRECT
@PreAuthorize("hasAuthority('SCOPE_user:read')")
public void method() { }
```

**Explanation**: Spring Security adds `SCOPE_` prefix by convention when extracting scopes from JWT.

---

### ❌ Using hasRole() for Scopes

```java
// WRONG
@PreAuthorize("hasRole('user:read')")
public void method() { }

// CORRECT
@PreAuthorize("hasAuthority('SCOPE_user:read')")
public void method() { }
```

**Explanation**: `hasRole()` checks for `ROLE_` prefix. Use `hasAuthority()` for scopes.

---

### ❌ Typos in Scope Names

```java
// WRONG
@PreAuthorize("hasAuthority('SCOPE_user:raed')")  // Typo: "raed"

// CORRECT
@PreAuthorize("hasAuthority('SCOPE_user:read')")
```

**Prevention**: Use constants:
```java
public class Scopes {
    public static final String USER_READ = "SCOPE_user:read";
    public static final String USER_WRITE = "SCOPE_user:write";
}

@PreAuthorize("hasAuthority(T(com.example.Scopes).USER_READ)")
public void method() { }
```

---

### ❌ Not Protecting Service Layer

```java
// WRONG - Only controller protected
@RestController
public class UserController {
    @PreAuthorize("hasAuthority('SCOPE_user:delete')")
    public void deleteUser(String id) {
        userService.delete(id);  // Can be called directly elsewhere!
    }
}

// CORRECT - Both controller and service protected
@Service
public class UserService {
    @PreAuthorize("hasAuthority('SCOPE_user:delete')")
    public void delete(String id) {
        userRepository.deleteById(id);
    }
}
```

---

### ❌ Complex Logic in @PreAuthorize

```java
// WRONG - Too complex, hard to test
@PreAuthorize("hasAuthority('SCOPE_user:write') AND (#request.age >= 18 OR #request.hasParentalConsent == true) AND (#request.country == 'US' OR #request.country == 'CA')")
public void method(CreateUserRequest request) { }

// CORRECT - Move to custom expression
@PreAuthorize("hasAuthority('SCOPE_user:write') AND @userValidationService.canCreateUser(#request)")
public void method(CreateUserRequest request) { }
```

---

## Best Practices

### ✅ Use Scope Constants

```java
public final class Scopes {
    // User scopes
    public static final String USER_READ = "SCOPE_user:read";
    public static final String USER_WRITE = "SCOPE_user:write";
    public static final String USER_DELETE = "SCOPE_user:delete";
    public static final String USER_MANAGE = "SCOPE_user:manage";
    
    // Profile scopes
    public static final String PROFILE_READ = "SCOPE_profile:read";
    public static final String PROFILE_WRITE = "SCOPE_profile:write";
    
    private Scopes() { }
}

// Usage
@PreAuthorize("hasAuthority(T(com.lanny.security.Scopes).USER_READ)")
public List<User> findAll() { }
```

---

### ✅ Document Required Scopes

```java
/**
 * Retrieves all users in the system.
 * 
 * @return list of all users
 * @requires SCOPE_user:read
 * @throws AccessDeniedException if user lacks required scope
 */
@GetMapping
@PreAuthorize("hasAuthority('SCOPE_user:read')")
public List<UserDto> getAllUsers() {
    return userService.findAll();
}
```

---

### ✅ Test All Authorization Paths

```java
@Nested
@DisplayName("Authorization Tests")
class AuthorizationTests {
    
    @Test
    @DisplayName("Should allow access with correct scope")
    void allowWithScope() { }
    
    @Test
    @DisplayName("Should deny access without scope")
    void denyWithoutScope() { }
    
    @Test
    @DisplayName("Should deny access with wrong scope")
    void denyWithWrongScope() { }
    
    @Test
    @DisplayName("Should deny access without authentication")
    void denyWithoutAuth() { }
}
```

---

### ✅ Fail Closed (Deny by Default)

```java
// CORRECT - Explicit check required
@GetMapping("/{id}")
@PreAuthorize("hasAuthority('SCOPE_user:read')")
public UserDto getUser(@PathVariable String id) { }

// WRONG - No protection
@GetMapping("/{id}")
public UserDto getUser(@PathVariable String id) { }
```

**Configuration**:
```java
@Configuration
public class SecurityConfig {
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
            .requestMatchers("/api/public/**").permitAll()
            .anyRequest().authenticated()  // ← Deny by default
        );
        return http.build();
    }
}
```

---

### ✅ Audit Authorization Failures

```java
@Component
public class AuthorizationAuditListener {
    
    private static final Logger log = LoggerFactory.getLogger(AuthorizationAuditListener.class);
    
    @EventListener
    public void onAuthorizationFailure(AuthorizationDeniedEvent event) {
        Authentication auth = event.getAuthentication().get();
        String username = auth.getName();
        String requiredAuthority = extractRequiredAuthority(event);
        
        log.warn("Authorization denied for user={}, required={}, granted={}",
            username,
            requiredAuthority,
            auth.getAuthorities()
        );
    }
}
```

---

## Quick Reference

| Pattern | Example | Use Case |
|---------|---------|----------|
| Single scope | `hasAuthority('SCOPE_user:read')` | Basic authorization |
| Multiple scopes (OR) | `hasAnyAuthority('SCOPE_user:read', 'SCOPE_user:manage')` | Flexible access |
| Multiple scopes (AND) | `hasAuthority('SCOPE_user:write') AND hasAuthority('SCOPE_role:manage')` | Stricter control |
| Role + Scope | `hasRole('ADMIN') AND hasAuthority('SCOPE_user:manage')` | Extra security layer |
| Path variable check | `#userId == authentication.name` | Ownership verification |
| Custom expression | `@customSecurityExpressions.canManage(#id, authentication)` | Complex business logic |

---

## References

- [Spring Security Method Security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [RBAC+ABAC Matrix](rbac-abac-matrix.md)
- [Scope Design Strategy](scope-design-strategy.md)
- [ADR-008: Stateless JWT Authentication](../adr/008-stateless-jwt-authentication.md)

---

**Last Updated**: 2025-12-26  
**Maintainer**: Security Team
