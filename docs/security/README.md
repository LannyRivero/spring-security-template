# 🔐 Documentación de Seguridad — Spring Security Template

Este directorio contiene documentación completa sobre el sistema de seguridad, autenticación y autorización de la plantilla.

---

## 📚 Índice de Documentos

### 🎯 **Authorization System (Comprehensive)**

1. **[RBAC+ABAC Authorization Matrix](rbac-abac-matrix.md)** ⭐ **START HERE**
   - Complete role and scope definitions
   - Authorization matrix mapping roles → scopes → endpoints
   - Implementation guide with code examples
   - Testing strategies
   - Extension guide

2. **[Scope Design Strategy](scope-design-strategy.md)**
   - Why scopes over roles-only?
   - Naming conventions (`resource:action`)
   - Granularity levels (coarse/medium/fine)
   - Scope hierarchies and patterns
   - Anti-patterns to avoid
   - Real-world examples (e-commerce, healthcare, banking)

3. **[Scope Implementation Guide](scope-implementation-guide.md)**
   - Spring Security configuration (`@EnableMethodSecurity`)
   - Controller protection with `@PreAuthorize`
   - Service layer protection (defense in depth)
   - Custom security expressions
   - Testing authorization (MockMvc, @WithMockUser)
   - Common pitfalls and best practices

4. **[Authorization Testing Examples](authorization-testing-examples.md)**
   - Controller tests (MockMvc)
   - Service layer tests
   - Integration tests (full auth flow)
   - Test utilities (`TestAuthenticationBuilder`, `TokenTestHelper`)
   - Edge cases and security tests
   - Concurrent access tests
   - Test coverage checklist

5. **[Extending the Authorization System](extending-authorization.md)**
   - Adding new scopes (step-by-step)
   - Adding new roles
   - Adding new resources
   - Database migration patterns (Flyway)
   - Scope assignment strategies
   - Rollback and deprecation procedures
   - Real-world examples

---

### 🔑 **Authentication & JWT**

- **[Authentication Documentation](authentication.md)**
  - Login flow
  - Token generation
  - Refresh token rotation

- **[JWT with Nimbus JOSE](jwt-nimbus.md)**
  - JWT structure and claims
  - Token validation
  - Signature algorithms (RSA vs HMAC)

- **[Key Management](key-management.md)**
  - RSA key generation
  - Key providers (classpath, filesystem, keystore)
  - Profile-based configuration
  - Key rotation strategies

---

### 🛡️ **Security Filters**

- **[Security Filters](filters.md)**
  - Filter chain overview
  - JwtAuthorizationFilter
  - SecurityHeadersFilter
  - LoginRateLimitingFilter
  - CorrelationIdFilter
  - AuthNoCacheFilter

---

### 📖 **Legacy Documents**

- `jwt-spec.md` - JWT specification (merged into jwt-nimbus.md)
- `roles-scopes-matrix.md` - Old matrix (replaced by rbac-abac-matrix.md)
- `filters-overview.md` - Filters overview (merged into filters.md)
- `preauthorize-policy.md` - @PreAuthorize policy (merged into scope-implementation-guide.md)
- `keys-management.md` - Key management (merged into key-management.md)

---

## 🚀 Quick Start Guide

### For Developers Implementing Authorization

1. **Read**: [RBAC+ABAC Matrix](rbac-abac-matrix.md) - Understand current roles and scopes
2. **Read**: [Scope Implementation Guide](scope-implementation-guide.md) - Learn `@PreAuthorize` patterns
3. **Implement**: Protect your endpoints with scopes
4. **Test**: Use [Authorization Testing Examples](authorization-testing-examples.md)

### For Architects/Security Team

1. **Read**: [Scope Design Strategy](scope-design-strategy.md) - Understand design philosophy
2. **Read**: [RBAC+ABAC Matrix](rbac-abac-matrix.md) - Review current authorization model
3. **Plan**: Use [Extending Authorization](extending-authorization.md) to add new roles/scopes

### For New Team Members

1. **Start**: [RBAC+ABAC Matrix](rbac-abac-matrix.md) - Overview of entire system
2. **Learn**: [Scope Design Strategy](scope-design-strategy.md) - Core concepts
3. **Practice**: [Authorization Testing Examples](authorization-testing-examples.md) - Hands-on examples

---

## 📊 Authorization Model Overview

```
User
 └─ has many Roles
     └─ ROLE_ADMIN
     └─ ROLE_USER
     └─ ROLE_FINANCE_MANAGER

Role
 └─ has many Scopes
     └─ user:read
     └─ user:write
     └─ profile:read
     └─ invoice:approve

Endpoint
 └─ protected by Scope(s)
     └─ @PreAuthorize("hasAuthority('SCOPE_user:read')")
```

**Key Principles**:
- ✅ **Hybrid RBAC+ABAC**: Roles contain scopes, endpoints check scopes
- ✅ **Fine-grained control**: Scopes use `resource:action` pattern
- ✅ **Defense in depth**: Controllers + Services protected
- ✅ **Stateless JWT**: Scopes embedded in access token
- ✅ **Extensible**: Easy to add new scopes/roles via migrations

---

## 🔗 Related Documentation

- **[ADR-008: Stateless JWT Authentication](../adr/008-stateless-jwt-authentication.md)**
- **[ADR-001: Nimbus JWT Library](../adr/001-nimbus-jwt-library.md)**
- **[ADR-002: RSA Signature Algorithm](../adr/002-rsa-signature-algorithm.md)**
- **[ADR-004: Refresh Token Strategy](../adr/004-refresh-token-strategy.md)**

---

## 🤝 Contributing

When adding new scopes or roles:

1. Follow [Extending Authorization](extending-authorization.md) guide
2. Update [RBAC+ABAC Matrix](rbac-abac-matrix.md)
3. Create Flyway migration
4. Write authorization tests
5. Update this README if needed

---

**Last Updated**: 2025-12-26  
**Maintainer**: Security Team