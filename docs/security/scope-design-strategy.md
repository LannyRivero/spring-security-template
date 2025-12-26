# 🎯 Scope Design Strategy

This document explains the **design philosophy** behind the scope system and provides guidelines for creating effective, maintainable scopes.

---

## Why Scopes Over Roles?

### The Problem with Role-Based Only Authorization

```java
// ❌ BAD: Hard-coded role checks
@PreAuthorize("hasRole('ADMIN')")
public void deleteUser(String userId) {
    // What if we need a "USER_MANAGER" role that can delete but not configure system?
    // We'd need to change this code everywhere
}

// ❌ BAD: Role explosion
// ROLE_ADMIN
// ROLE_USER
// ROLE_SUPER_ADMIN
// ROLE_USER_ADMIN
// ROLE_CONTENT_ADMIN
// ROLE_BILLING_ADMIN
// ... 50 more roles later ...
```

### The Scope Solution

```java
// ✅ GOOD: Scope-based authorization
@PreAuthorize("hasAuthority('SCOPE_user:delete')")
public void deleteUser(String userId) {
    // Any role with "user:delete" scope can call this
    // ROLE_ADMIN → has user:delete
    // ROLE_USER_MANAGER → has user:delete
    // ROLE_SUPPORT_LEAD → has user:delete
}
```

**Benefits**:
- ✅ **Granularity**: One role can have many scopes
- ✅ **Flexibility**: Add/remove scopes without changing code
- ✅ **Clarity**: Scope name describes exact permission
- ✅ **Reusability**: Multiple roles can share same scope
- ✅ **Testability**: Test scopes, not role hierarchies

---

## Scope Naming Convention

### Format: `resource:action`

```
resource:action
   ↓       ↓
profile:read
   ↓       ↓
 what    how
```

### Resource Names

**Rules**:
- Lowercase
- Singular form (not plural)
- Noun (entity name)
- Hyphen-separated for multi-word (`credit-card`, `user-profile`)

**Examples**:
```
✅ user
✅ profile
✅ simulation
✅ audit
✅ system
✅ credit-card
✅ invoice

❌ users (plural)
❌ User (uppercase)
❌ user_profile (underscore)
❌ deleteUser (verb)
```

### Action Names

**Standard CRUD Actions**:
```
read    → View/retrieve data
write   → Create/update data
delete  → Remove data
manage  → Full CRUD + special operations
```

**Extended Actions**:
```
execute   → Run/trigger operations (e.g., simulation:execute)
export    → Download/extract data (e.g., audit:export)
import    → Upload/ingest data (e.g., data:import)
approve   → Workflow approval (e.g., request:approve)
config    → Configure settings (e.g., system:config)
impersonate → Assume identity (e.g., user:impersonate)
```

**Examples**:
```
✅ profile:read
✅ user:write
✅ simulation:execute
✅ audit:export
✅ system:config

❌ profile:view (use "read")
❌ user:update (use "write")
❌ simulation:run (use "execute")
❌ audit:download (use "export")
```

---

## Scope Granularity Levels

### Level 1: Coarse-Grained (Recommended Starting Point)

**One scope per resource**:
```
user:manage     → All user operations (CRUD)
profile:manage  → All profile operations
audit:manage    → All audit operations
```

**When to use**:
- ✅ Simple applications
- ✅ MVP/prototypes
- ✅ Small teams

**Pros**: Simple, fast to implement  
**Cons**: Less flexible, all-or-nothing access

---

### Level 2: Medium-Grained (Recommended for Production)

**Separate read/write**:
```
user:read    → View users
user:write   → Create/update users
user:delete  → Delete users

profile:read  → View own profile
profile:write → Update own profile
```

**When to use**:
- ✅ Production applications
- ✅ Enterprise environments
- ✅ Compliance requirements (read-only auditors)

**Pros**: Balanced flexibility, clear intent  
**Cons**: More scopes to manage

---

### Level 3: Fine-Grained (Use Sparingly)

**Action-specific scopes**:
```
user:create
user:update
user:view-details
user:view-list
user:activate
user:deactivate
user:reset-password
user:assign-role
```

**When to use**:
- ⚠️ Highly regulated industries (banking, healthcare)
- ⚠️ Complex authorization workflows
- ⚠️ Attribute-based access control (ABAC)

**Pros**: Maximum control  
**Cons**: Scope explosion, maintenance burden

---

## Scope Hierarchies

### Implicit Scope Inclusion

Some scopes imply others:

```
user:manage
  ↓ includes
  - user:read
  - user:write
  - user:delete
  - user:*
```

**Implementation** (in `ScopePolicy`):
```java
@Override
public Set<Scope> resolveScopes(Set<Role> roles) {
    Set<Scope> resolved = new HashSet<>();
    
    for (Role role : roles) {
        for (Scope scope : role.scopes()) {
            resolved.add(scope);
            
            // Expand "manage" scopes
            if (scope.action().equals("manage")) {
                String resource = scope.resource();
                resolved.add(Scope.of(resource + ":read"));
                resolved.add(Scope.of(resource + ":write"));
                resolved.add(Scope.of(resource + ":delete"));
            }
        }
    }
    
    return resolved;
}
```

**Usage**:
```java
// Grant "user:manage" in database
// User automatically gets:
//   - user:read
//   - user:write
//   - user:delete
//   - user:manage
```

---

## Scope Organization Patterns

### Pattern 1: By Resource (Recommended)

Group scopes by the resource they protect:

```
Profile Resource:
  - profile:read
  - profile:write
  - profile:delete

User Resource:
  - user:read
  - user:write
  - user:delete
  - user:manage

Simulation Resource:
  - simulation:read
  - simulation:write
  - simulation:execute
  - simulation:delete
```

**Database structure**:
```sql
scopes:
  - profile:read
  - profile:write
  - user:read
  - user:write
  - simulation:read
  - simulation:execute
```

---

### Pattern 2: By Domain Module

For microservices, prefix with module:

```
auth:login
auth:register
auth:password-reset

billing:invoice-read
billing:invoice-write
billing:payment-process

catalog:product-read
catalog:product-write
```

**When to use**:
- Microservices architecture
- Separate bounded contexts
- Different deployment units

---

### Pattern 3: By Tenant (Multi-Tenancy)

Include tenant ID in scope (advanced):

```
tenant-123:user:read
tenant-123:user:write
tenant-456:user:read
```

**Not recommended** - Use claims or context instead.

---

## Wildcard Scopes (Advanced)

### Explicit Wildcards

Grant all actions on a resource:

```
user:*  → All user operations (read, write, delete, manage, etc.)
*:read  → Read all resources
*:*     → God mode (use with extreme caution)
```

**Implementation**:
```java
public boolean hasScope(String requestedScope) {
    return grantedScopes.stream()
        .anyMatch(granted -> matchesPattern(granted, requestedScope));
}

private boolean matchesPattern(String granted, String requested) {
    if (granted.equals(requested)) return true;
    if (granted.equals("*:*")) return true;
    
    String[] grantedParts = granted.split(":");
    String[] requestedParts = requested.split(":");
    
    if (grantedParts[0].equals("*") || grantedParts[0].equals(requestedParts[0])) {
        if (grantedParts[1].equals("*") || grantedParts[1].equals(requestedParts[1])) {
            return true;
        }
    }
    
    return false;
}
```

**Security Warning**: ⚠️ Wildcards are powerful but dangerous. Use sparingly.

---

## Scope Lifecycle

### 1. Design Phase

- **Identify resources** (entities, APIs, operations)
- **Define actions** (read, write, delete, custom)
- **Create scope catalog** (document in matrix)
- **Review with security team**

### 2. Implementation Phase

```sql
-- Create scope
INSERT INTO scopes (id, name) VALUES (UUID(), 'resource:action');

-- Assign to role
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id FROM roles r, scopes s
WHERE r.name = 'ROLE_X' AND s.name = 'resource:action';
```

### 3. Protection Phase

```java
@PreAuthorize("hasAuthority('SCOPE_resource:action')")
public void protectedMethod() { }
```

### 4. Testing Phase

```java
@Test
void shouldAllowAccessWithScope() {
    String token = tokenProvider.generateAccessToken(
        "user", List.of("ROLE_USER"), List.of("resource:action"), Duration.ofMinutes(15)
    );
    
    mockMvc.perform(get("/api/endpoint")
            .header("Authorization", "Bearer " + token))
        .andExpect(status().isOk());
}
```

### 5. Documentation Phase

- Update [RBAC+ABAC Matrix](rbac-abac-matrix.md)
- Update OpenAPI security schemes
- Notify team of new scopes

---

## Anti-Patterns to Avoid

### ❌ Role-Scope Coupling

```sql
-- DON'T create role-specific scopes
INSERT INTO scopes (name) VALUES ('admin:everything');
INSERT INTO scopes (name) VALUES ('user:self-only');

-- DO create resource-action scopes
INSERT INTO scopes (name) VALUES ('user:read');
INSERT INTO scopes (name) VALUES ('user:write');
```

### ❌ Action-First Naming

```sql
-- DON'T use action-first
INSERT INTO scopes (name) VALUES ('read:user');
INSERT INTO scopes (name) VALUES ('write:profile');

-- DO use resource-first
INSERT INTO scopes (name) VALUES ('user:read');
INSERT INTO scopes (name) VALUES ('profile:write');
```

### ❌ Scope Explosion

```sql
-- DON'T create too many fine-grained scopes
user:create
user:update
user:update-name
user:update-email
user:update-password
user:activate
user:deactivate
-- ... 20 more user scopes ...

-- DO group related actions
user:read
user:write
user:manage
```

### ❌ Business Logic in Scopes

```sql
-- DON'T encode business logic
user:delete-if-inactive-for-30-days
invoice:approve-if-under-1000

-- DO keep scopes simple
user:delete
invoice:approve
```

---

## Checklist for New Scopes

Before adding a new scope, answer these questions:

- [ ] **Resource name is clear and singular?** (e.g., `user`, not `users`)
- [ ] **Action is standard or well-justified?** (prefer `read/write/delete`)
- [ ] **Scope doesn't duplicate existing ones?** (check catalog first)
- [ ] **Scope is technology-agnostic?** (no `user:sql-delete`, just `user:delete`)
- [ ] **Scope is testable?** (can write unit test for it)
- [ ] **Scope is documented?** (added to matrix)
- [ ] **Migration created?** (Flyway SQL)
- [ ] **Assigned to appropriate roles?**
- [ ] **Endpoints protected with @PreAuthorize?**
- [ ] **Tests written?**

---

## Examples from Real Projects

### E-Commerce Platform

```
product:read
product:write
product:delete
order:read
order:write
order:fulfill
order:cancel
payment:process
payment:refund
inventory:read
inventory:adjust
```

### Healthcare System (HIPAA Compliant)

```
patient:read
patient:write
patient:phi-access    (Protected Health Information)
prescription:read
prescription:write
prescription:approve
audit:read
audit:export
consent:manage
```

### Banking Application (PCI-DSS)

```
account:read
account:write
transaction:read
transaction:create
payment:initiate
payment:approve      (dual control)
card:read
card:activate
card:deactivate
audit:read
compliance:report
```

---

## References

- [RBAC+ABAC Matrix](rbac-abac-matrix.md) - Complete authorization matrix
- [OAuth 2.0 Scopes](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3)
- [OWASP - Access Control Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Access_Control_Cheat_Sheet.html)
- [Google Cloud IAM - Permission Design](https://cloud.google.com/iam/docs/overview)
- [AWS IAM - Actions and Permissions](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_action.html)

---

**Last Updated**: 2025-12-26  
**Maintainer**: Security Team
