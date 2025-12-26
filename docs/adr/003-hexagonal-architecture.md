# ADR-003: Hexagonal Architecture with Domain-Driven Design

## Status

**Accepted**

**Date**: 2025-12-26

## Context

This Spring Security Template is designed to be:
- **Reusable** across multiple projects and domains
- **Maintainable** with clear separation of concerns
- **Testable** with isolated business logic
- **Extensible** to support future requirements without major refactoring
- **Framework-independent** in its core business rules

Traditional layered architecture (Controller → Service → Repository) has limitations:
- Business logic often leaks into controllers or repositories
- High coupling to frameworks (Spring, JPA, etc.)
- Difficult to test without infrastructure
- Hard to swap implementations (e.g., JPA → MongoDB)
- No clear boundaries between technical and business code

We need an architectural style that:
- **Protects business logic** from infrastructure details
- **Enforces clear boundaries** between layers
- **Enables independent testing** of domain rules
- **Supports multiple adapters** (REST, GraphQL, messaging, CLI)
- **Aligns with enterprise patterns** (DDD, Clean Architecture)

## Decision

We will use **Hexagonal Architecture (Ports & Adapters)** combined with **Domain-Driven Design (DDD) tactical patterns**.

### Architecture Structure

```
src/main/java/
├── domain/                     # Pure business logic (no dependencies)
│   ├── model/                  # Aggregates, Entities, Value Objects
│   │   ├── User.java           # Aggregate Root
│   │   ├── Role.java           # Entity
│   │   ├── Scope.java          # Entity
│   │   └── UserStatus.java     # Enum
│   ├── valueobject/            # Value Objects (immutable)
│   │   ├── UserId.java
│   │   ├── Username.java
│   │   ├── EmailAddress.java
│   │   └── PasswordHash.java
│   ├── policy/                 # Domain policies (business rules)
│   │   ├── ScopePolicy.java
│   │   └── PasswordPolicy.java
│   ├── service/                # Domain services (stateless business logic)
│   │   └── PasswordHasher.java
│   └── exception/              # Domain exceptions
│       ├── UserLockedException.java
│       └── InvalidCredentialsException.java
│
├── application/                # Application logic (use cases)
│   └── auth/
│       ├── port/
│       │   ├── in/             # Inbound ports (use case interfaces)
│       │   │   └── AuthUseCase.java
│       │   └── out/            # Outbound ports (gateways)
│       │       ├── TokenProvider.java
│       │       ├── UserAccountGateway.java
│       │       └── TokenBlacklistGateway.java
│       ├── service/            # Use case implementations
│       │   └── AuthUseCaseImpl.java
│       ├── command/            # Commands (write operations)
│       │   ├── LoginCommand.java
│       │   └── RefreshCommand.java
│       ├── query/              # Queries (read operations)
│       │   └── MeQuery.java
│       └── result/             # Use case results (DTOs)
│           └── JwtResult.java
│
└── infrastructure/             # Adapters (frameworks, I/O)
    ├── web/                    # Inbound REST adapter
    │   └── auth/
    │       ├── controller/
    │       │   └── AuthController.java
    │       └── dto/
    │           ├── AuthRequest.java
    │           └── AuthResponse.java
    ├── jwt/                    # Outbound JWT adapter
    │   └── nimbus/
    │       └── NimbusJwtTokenProvider.java
    ├── persistence/            # Outbound persistence adapter
    │   └── jpa/
    │       ├── UserAccountJpaAdapter.java
    │       └── entity/
    │           └── UserEntity.java
    ├── security/               # Spring Security configuration
    │   ├── SecurityConfig.java
    │   └── filter/
    │       └── JwtAuthorizationFilter.java
    └── config/                 # Wiring (dependency injection)
        └── AuthUseCaseConfig.java
```

### Key Principles

1. **Domain Layer Independence**
   - Zero external dependencies (no Spring, no JPA, no Jackson)
   - Pure Java (Java 21 language features only)
   - Business rules live here

2. **Dependency Rule**
   - Dependencies point **inward** only
   - Domain ← Application ← Infrastructure
   - Infrastructure depends on application ports (interfaces)
   - Application depends on domain models
   - Domain depends on nothing

3. **Ports & Adapters**
   - **Inbound ports**: Interfaces for use cases (`AuthUseCase`)
   - **Outbound ports**: Interfaces for external dependencies (`TokenProvider`, `UserAccountGateway`)
   - **Adapters**: Implementations of ports (REST controller, JPA repository, JWT library)

4. **DDD Tactical Patterns**
   - **Aggregates**: User (Aggregate Root) controls Role and Scope lifecycle
   - **Value Objects**: UserId, Username, EmailAddress (immutable, validated)
   - **Domain Events**: `UserLoggedInEvent`, `RefreshTokenUsedEvent`
   - **Repositories**: Abstracted as `UserAccountGateway` (outbound port)

## Alternatives Considered

### Alternative 1: Traditional Layered Architecture

**Structure**: Controller → Service → Repository

**Pros**:
- ✅ Simple and familiar to most developers
- ✅ Less boilerplate (no ports/adapters)
- ✅ Faster initial development

**Cons**:
- ❌ Business logic leaks into controllers or repositories
- ❌ High coupling to Spring and JPA
- ❌ Difficult to test (requires mocking infrastructure)
- ❌ Hard to swap implementations (tight coupling)
- ❌ No clear boundaries (everything is a "Service")

**Why rejected**: This template targets **enterprise-grade reusability**. Layered architecture becomes a maintenance burden as complexity grows.

### Alternative 2: Clean Architecture (Uncle Bob)

**Pros**:
- ✅ Similar benefits to Hexagonal Architecture
- ✅ Well-documented (Clean Architecture book)
- ✅ Emphasizes use cases

**Cons**:
- ⚠️ More prescriptive (strict concentric circles)
- ⚠️ Can be over-engineered for some contexts

**Why not rejected**: Hexagonal Architecture and Clean Architecture are **very similar**. We use Hexagonal terminology but follow Clean Architecture principles (Dependency Rule, Use Cases). This ADR documents our interpretation.

### Alternative 3: Modular Monolith (Domain Modules)

**Structure**: `/auth`, `/users`, `/billing` as independent modules

**Pros**:
- ✅ Good for large monoliths with multiple bounded contexts
- ✅ Clear module boundaries

**Cons**:
- ⚠️ Overkill for a security template (single bounded context)
- ⚠️ Requires build-time module enforcement (Jigsaw, ArchUnit)

**Why rejected**: This template focuses on the **authentication/authorization bounded context** only. Modular monolith is more relevant for multi-domain applications.

## Consequences

### Positive

- ✅ **Testability**: Domain logic tested without Spring context (pure unit tests)
- ✅ **Framework independence**: Can swap Spring for Micronaut, Quarkus, etc.
- ✅ **Adapter flexibility**: Add GraphQL, gRPC, or CLI without touching domain
- ✅ **Clear boundaries**: Developers know where to put code (no "misc" packages)
- ✅ **Maintainability**: Changes in infrastructure don't affect business logic
- ✅ **Reusability**: Domain models can be extracted to shared libraries
- ✅ **Screaming architecture**: Package structure reveals what the system does (auth)
- ✅ **Onboarding**: New developers understand structure quickly

### Negative

- ⚠️ **More boilerplate**: Interfaces for ports, commands, queries, results
- ⚠️ **Learning curve**: Developers unfamiliar with Hexagonal/DDD need training
- ⚠️ **Initial setup time**: More files and packages to create upfront
- ⚠️ **Over-engineering risk**: Can be excessive for trivial CRUD operations

### Neutral

- ℹ️ Mappers required between layers (DTOs → Commands, Domain → Results)
- ℹ️ Dependency injection becomes explicit (ports wired in `@Configuration`)

## Implementation Guidelines

### 1. Domain Layer Rules

```java
// ✅ GOOD: Pure domain logic, no framework dependencies
public final class User {
    private final UserId id;
    private final Username username;
    
    public void authenticate(String rawPassword, PasswordHasher hasher) {
        if (status == UserStatus.LOCKED) {
            throw new UserLockedException(username);
        }
        if (!hasher.matches(rawPassword, passwordHash)) {
            throw new InvalidCredentialsException();
        }
    }
}

// ❌ BAD: Framework dependencies in domain
@Entity // NO! JPA leaks into domain
public class User {
    @Id
    @GeneratedValue
    private Long id; // NO! Exposes database identity strategy
}
```

### 2. Application Layer (Use Cases)

```java
// Inbound port (interface for use case)
public interface AuthUseCase {
    JwtResult login(LoginCommand command);
    JwtResult refresh(RefreshCommand command);
    MeResult me(MeQuery query);
}

// Implementation (use case orchestration)
@RequiredArgsConstructor
public class AuthUseCaseImpl implements AuthUseCase {
    private final UserAccountGateway userGateway; // Outbound port
    private final TokenProvider tokenProvider;    // Outbound port
    private final PasswordHasher passwordHasher;  // Domain service
    
    @Override
    public JwtResult login(LoginCommand command) {
        User user = userGateway.findByUsername(command.username())
            .orElseThrow(InvalidCredentialsException::new);
        
        user.authenticate(command.password(), passwordHasher);
        
        String accessToken = tokenProvider.generateAccessToken(/* ... */);
        String refreshToken = tokenProvider.generateRefreshToken(/* ... */);
        
        return new JwtResult(accessToken, refreshToken, /* ... */);
    }
}
```

### 3. Infrastructure Layer (Adapters)

```java
// Inbound adapter (REST)
@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthUseCase authUseCase; // Depends on inbound port
    private final AuthMapper mapper;       // DTO ↔ Command mapping
    
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody AuthRequest request) {
        LoginCommand command = mapper.toCommand(request);
        JwtResult result = authUseCase.login(command);
        AuthResponse response = mapper.toResponse(result);
        return ResponseEntity.ok(response);
    }
}

// Outbound adapter (JPA)
@Repository
@Profile({"dev", "prod"})
@RequiredArgsConstructor
public class UserAccountJpaAdapter implements UserAccountGateway {
    private final UserJpaRepository jpaRepository;
    private final UserEntityMapper mapper;
    
    @Override
    public Optional<User> findByUsername(Username username) {
        return jpaRepository.findByUsername(username.value())
            .map(mapper::toDomain); // Entity → Domain
    }
}
```

## Testing Strategy

### Domain Tests (Pure Unit)
```java
class UserTest {
    @Test
    void shouldThrowWhenUserIsLocked() {
        User user = User.rehydrate(/* ... status = LOCKED ... */);
        
        assertThatThrownBy(() -> user.authenticate("password", hasher))
            .isInstanceOf(UserLockedException.class);
    }
}
```

### Application Tests (Use Case)
```java
class AuthUseCaseImplTest {
    @Mock UserAccountGateway userGateway;
    @Mock TokenProvider tokenProvider;
    
    @Test
    void shouldReturnTokensWhenCredentialsAreValid() {
        // Given
        when(userGateway.findByUsername(any())).thenReturn(Optional.of(user));
        when(tokenProvider.generateAccessToken(/* ... */)).thenReturn("token");
        
        // When
        JwtResult result = authUseCase.login(command);
        
        // Then
        assertThat(result.accessToken()).isNotEmpty();
    }
}
```

### Infrastructure Tests (Integration)
```java
@SpringBootTest
@Transactional
class UserAccountJpaAdapterTest {
    @Autowired UserAccountGateway gateway;
    
    @Test
    void shouldPersistAndRetrieveUser() {
        User user = User.createNew(/* ... */);
        gateway.save(user);
        
        Optional<User> retrieved = gateway.findByUsername(user.getUsername());
        
        assertThat(retrieved).isPresent();
    }
}
```

## References

- [Alistair Cockburn - Hexagonal Architecture](https://alistair.cockburn.us/hexagonal-architecture/)
- [Robert C. Martin - Clean Architecture](https://blog.cleancoder.com/uncle-bob/2012/08/13/the-clean-architecture.html)
- [Eric Evans - Domain-Driven Design](https://www.domainlanguage.com/ddd/)
- [Vaughn Vernon - Implementing Domain-Driven Design](https://vaughnvernon.com/)
- [Tom Hombergs - Get Your Hands Dirty on Clean Architecture](https://reflectoring.io/book/)
- [ArchUnit - Architecture Testing](https://www.archunit.org/)

## Review

**Reviewers**: Architecture Guild, Tech Leads
**Approved by**: Chief Architect
**Review date**: 2025-12-26
