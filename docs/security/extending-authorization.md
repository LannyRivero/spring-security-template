# 🔧 Extending the Authorization System

Complete guide to adding new roles, scopes, and resources to the authorization system.

---

## Table of Contents

1. [Adding New Scopes](#adding-new-scopes)
2. [Adding New Roles](#adding-new-roles)
3. [Adding New Resources](#adding-new-resources)
4. [Scope Assignment Strategies](#scope-assignment-strategies)
5. [Database Migration Patterns](#database-migration-patterns)
6. [Rollback & Deprecation](#rollback--deprecation)
7. [Real-World Examples](#real-world-examples)

---

## Adding New Scopes

### Step-by-Step Process

#### 1. Design the Scope

Ask yourself:
- **What resource** does this protect? (e.g., `invoice`, `payment`, `report`)
- **What action** is allowed? (e.g., `read`, `write`, `delete`, `approve`)
- **Is it granular enough?** (avoid over-engineering)
- **Does it follow naming convention?** (`resource:action`)

**Example**: Adding invoice management scopes

```
invoice:read    → View invoices
invoice:write   → Create/update invoices
invoice:delete  → Delete invoices
invoice:approve → Approve invoices (workflow action)
invoice:export  → Export invoices to PDF/Excel
```

---

#### 2. Create Flyway Migration

Create new migration file: `V{N}__add_invoice_scopes.sql`

```sql
-- V6__add_invoice_scopes.sql

-- Add new scopes
INSERT INTO scopes (id, name, description, created_at)
VALUES
    (UUID(), 'invoice:read', 'View invoices', NOW()),
    (UUID(), 'invoice:write', 'Create and update invoices', NOW()),
    (UUID(), 'invoice:delete', 'Delete invoices', NOW()),
    (UUID(), 'invoice:approve', 'Approve invoices for payment', NOW()),
    (UUID(), 'invoice:export', 'Export invoices to PDF or Excel', NOW());

-- Grant scopes to existing roles
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_ADMIN'
  AND s.name IN ('invoice:read', 'invoice:write', 'invoice:delete', 'invoice:approve', 'invoice:export');

-- Grant read-only access to accountants
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_ACCOUNTANT'
  AND s.name IN ('invoice:read', 'invoice:export');

-- Grant write access to finance managers
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_FINANCE_MANAGER'
  AND s.name IN ('invoice:read', 'invoice:write', 'invoice:approve', 'invoice:export');
```

**File location**: `src/main/resources/db/migration/V6__add_invoice_scopes.sql`

---

#### 3. Run Migration

```bash
# Development environment
mvn flyway:migrate

# Production (automated via CI/CD)
# Flyway runs automatically on application startup
```

**Verify**:
```sql
SELECT * FROM scopes WHERE name LIKE 'invoice:%';

SELECT r.name, s.name
FROM roles r
JOIN role_scopes rs ON r.id = rs.role_id
JOIN scopes s ON rs.scope_id = s.id
WHERE s.name LIKE 'invoice:%'
ORDER BY r.name, s.name;
```

---

#### 4. Update Domain Model (Optional)

If you need scope constants for type safety:

```java
package com.lanny.spring_security_template.domain.model;

public final class Scopes {
    // User scopes
    public static final String USER_READ = "user:read";
    public static final String USER_WRITE = "user:write";
    public static final String USER_DELETE = "user:delete";
    public static final String USER_MANAGE = "user:manage";
    
    // Profile scopes
    public static final String PROFILE_READ = "profile:read";
    public static final String PROFILE_WRITE = "profile:write";
    
    // Invoice scopes (NEW)
    public static final String INVOICE_READ = "invoice:read";
    public static final String INVOICE_WRITE = "invoice:write";
    public static final String INVOICE_DELETE = "invoice:delete";
    public static final String INVOICE_APPROVE = "invoice:approve";
    public static final String INVOICE_EXPORT = "invoice:export";
    
    private Scopes() {
        throw new UnsupportedOperationException("Utility class");
    }
}
```

---

#### 5. Protect Endpoints

```java
package com.lanny.spring_security_template.application.rest;

import com.lanny.spring_security_template.domain.model.Scopes;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/invoices")
public class InvoiceController {

    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_' + T(com.lanny.spring_security_template.domain.model.Scopes).INVOICE_READ)")
    public List<InvoiceDto> getAllInvoices() {
        return invoiceService.findAll();
    }

    @PostMapping
    @PreAuthorize("hasAuthority('SCOPE_invoice:write')")
    public InvoiceDto createInvoice(@RequestBody CreateInvoiceRequest request) {
        return invoiceService.create(request);
    }

    @PutMapping("/{id}/approve")
    @PreAuthorize("hasAuthority('SCOPE_invoice:approve')")
    public InvoiceDto approveInvoice(@PathVariable String id) {
        return invoiceService.approve(id);
    }

    @GetMapping("/{id}/export")
    @PreAuthorize("hasAuthority('SCOPE_invoice:export')")
    public ResponseEntity<byte[]> exportInvoice(@PathVariable String id) {
        byte[] pdf = invoiceService.exportToPdf(id);
        return ResponseEntity.ok()
            .header("Content-Disposition", "attachment; filename=invoice-" + id + ".pdf")
            .contentType(MediaType.APPLICATION_PDF)
            .body(pdf);
    }
}
```

---

#### 6. Write Tests

```java
@SpringBootTest
@AutoConfigureMockMvc
class InvoiceControllerAuthorizationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private TokenProvider tokenProvider;

    @Test
    void shouldAllowInvoiceReadWithCorrectScope() throws Exception {
        String token = generateToken("user", List.of("invoice:read"));

        mockMvc.perform(get("/api/invoices")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isOk());
    }

    @Test
    void shouldDenyInvoiceApprovalWithoutScope() throws Exception {
        String token = generateToken("user", List.of("invoice:read"));

        mockMvc.perform(put("/api/invoices/inv-123/approve")
                .header("Authorization", "Bearer " + token))
            .andExpect(status().isForbidden());
    }

    private String generateToken(String username, List<String> scopes) {
        return tokenProvider.generateAccessToken(
            username,
            List.of("ROLE_USER"),
            scopes,
            Duration.ofMinutes(15)
        );
    }
}
```

---

#### 7. Update Documentation

Update [RBAC+ABAC Matrix](rbac-abac-matrix.md):

```markdown
### Invoice Scopes

| Scope | Description | Assigned to Roles |
|-------|-------------|-------------------|
| `invoice:read` | View invoices | ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_FINANCE_MANAGER |
| `invoice:write` | Create/update invoices | ROLE_ADMIN, ROLE_FINANCE_MANAGER |
| `invoice:delete` | Delete invoices | ROLE_ADMIN |
| `invoice:approve` | Approve invoices for payment | ROLE_ADMIN, ROLE_FINANCE_MANAGER |
| `invoice:export` | Export invoices to PDF/Excel | ROLE_ADMIN, ROLE_ACCOUNTANT, ROLE_FINANCE_MANAGER |
```

---

## Adding New Roles

### Step-by-Step Process

#### 1. Design the Role

Ask yourself:
- **What is the business function?** (e.g., Finance Manager, Support Agent)
- **What scopes does it need?** (existing + new)
- **Does it replace an existing role?** (consider deprecation strategy)
- **What is the hierarchy?** (if applicable)

**Example**: Adding `ROLE_FINANCE_MANAGER` role

**Scopes**:
- `invoice:read`
- `invoice:write`
- `invoice:approve`
- `invoice:export`
- `profile:read` (basic profile access)

---

#### 2. Create Flyway Migration

Create new migration file: `V{N}__add_finance_manager_role.sql`

```sql
-- V7__add_finance_manager_role.sql

-- Create role
INSERT INTO roles (id, name, description, created_at)
VALUES (UUID(), 'ROLE_FINANCE_MANAGER', 'Finance Manager with invoice approval permissions', NOW());

-- Assign scopes to role
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_FINANCE_MANAGER'
  AND s.name IN (
    'invoice:read',
    'invoice:write',
    'invoice:approve',
    'invoice:export',
    'profile:read'
  );

-- Optionally, assign role to specific users
-- INSERT INTO user_roles (user_id, role_id)
-- SELECT u.id, r.id
-- FROM users u
-- CROSS JOIN roles r
-- WHERE u.username = 'jane.doe'
--   AND r.name = 'ROLE_FINANCE_MANAGER';
```

---

#### 3. Update Domain Model

```java
package com.lanny.spring_security_template.domain.model;

public enum UserRole {
    ADMIN("ROLE_ADMIN", "System Administrator"),
    USER("ROLE_USER", "Regular User"),
    FINANCE_MANAGER("ROLE_FINANCE_MANAGER", "Finance Manager"),  // NEW
    ACCOUNTANT("ROLE_ACCOUNTANT", "Accountant"),                  // NEW
    SUPPORT("ROLE_SUPPORT", "Support Agent");                     // NEW
    
    private final String name;
    private final String description;
    
    UserRole(String name, String description) {
        this.name = name;
        this.description = description;
    }
    
    public String getName() {
        return name;
    }
    
    public String getDescription() {
        return description;
    }
}
```

---

#### 4. Update User Assignment Logic

```java
@Service
public class RoleAssignmentService {
    
    @Autowired
    private RoleRepository roleRepository;
    
    public void assignRole(User user, UserRole role) {
        Role domainRole = roleRepository.findByName(role.getName())
            .orElseThrow(() -> new NotFoundException("Role not found: " + role.getName()));
        
        user.addRole(domainRole);
    }
    
    public void removeRole(User user, UserRole role) {
        user.removeRoleByName(role.getName());
    }
    
    /**
     * Assign default role to new users
     */
    public void assignDefaultRole(User user) {
        assignRole(user, UserRole.USER);
    }
}
```

---

#### 5. Test Role Assignment

```java
@SpringBootTest
class RoleAssignmentServiceTest {
    
    @Autowired
    private RoleAssignmentService roleAssignmentService;
    
    @Autowired
    private UserRepository userRepository;
    
    @Test
    void shouldAssignFinanceManagerRole() {
        User user = userRepository.findByUsername("jane.doe")
            .orElseThrow();
        
        roleAssignmentService.assignRole(user, UserRole.FINANCE_MANAGER);
        
        assertTrue(user.hasRole("ROLE_FINANCE_MANAGER"));
        assertTrue(user.hasScope("invoice:approve"));
    }
}
```

---

#### 6. Update OpenAPI Documentation

```java
@Configuration
public class OpenApiConfig {
    
    @Bean
    public OpenAPI customOpenAPI() {
        return new OpenAPI()
            .info(new Info()
                .title("Spring Security Template API")
                .version("1.0.0"))
            .components(new Components()
                .addSecuritySchemes("bearer-jwt", new SecurityScheme()
                    .type(SecurityScheme.Type.HTTP)
                    .scheme("bearer")
                    .bearerFormat("JWT")
                    .description("Available roles: ROLE_ADMIN, ROLE_USER, ROLE_FINANCE_MANAGER, ROLE_ACCOUNTANT")));
    }
}
```

---

## Adding New Resources

### Example: Adding Audit Logs

#### 1. Create Scopes

```sql
-- V8__add_audit_scopes.sql
INSERT INTO scopes (id, name, description, created_at)
VALUES
    (UUID(), 'audit:read', 'View audit logs', NOW()),
    (UUID(), 'audit:export', 'Export audit logs', NOW()),
    (UUID(), 'audit:delete', 'Delete old audit logs (admin only)', NOW());
```

#### 2. Assign to Roles

```sql
-- Grant audit access to admins
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_ADMIN'
  AND s.name IN ('audit:read', 'audit:export', 'audit:delete');

-- Grant read-only audit access to compliance officers
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_COMPLIANCE_OFFICER'
  AND s.name IN ('audit:read', 'audit:export');
```

#### 3. Create Controller

```java
@RestController
@RequestMapping("/api/audit")
public class AuditController {
    
    @GetMapping
    @PreAuthorize("hasAuthority('SCOPE_audit:read')")
    public Page<AuditLogDto> getAuditLogs(
        @RequestParam(defaultValue = "0") int page,
        @RequestParam(defaultValue = "50") int size
    ) {
        return auditService.findAll(PageRequest.of(page, size));
    }
    
    @GetMapping("/export")
    @PreAuthorize("hasAuthority('SCOPE_audit:export')")
    public ResponseEntity<byte[]> exportAuditLogs(
        @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate startDate,
        @RequestParam @DateTimeFormat(iso = DateTimeFormat.ISO.DATE) LocalDate endDate
    ) {
        byte[] csv = auditService.exportToCsv(startDate, endDate);
        return ResponseEntity.ok()
            .header("Content-Disposition", "attachment; filename=audit-logs.csv")
            .contentType(MediaType.parseMediaType("text/csv"))
            .body(csv);
    }
    
    @DeleteMapping("/purge")
    @PreAuthorize("hasAuthority('SCOPE_audit:delete')")
    public void purgeOldLogs(@RequestParam int daysOld) {
        auditService.deleteLogsOlderThan(daysOld);
    }
}
```

---

## Scope Assignment Strategies

### Strategy 1: Broad Access (Recommended for Small Teams)

```sql
-- Give ROLE_ADMIN all scopes
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_ADMIN';
```

**Pros**: Simple, fast to implement  
**Cons**: Less granular control

---

### Strategy 2: Granular Access (Recommended for Enterprise)

```sql
-- Assign only necessary scopes per role
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE (r.name = 'ROLE_ADMIN' AND s.name IN ('user:manage', 'system:config', 'audit:read'))
   OR (r.name = 'ROLE_FINANCE_MANAGER' AND s.name IN ('invoice:read', 'invoice:write', 'invoice:approve'))
   OR (r.name = 'ROLE_SUPPORT' AND s.name IN ('user:read', 'profile:read'));
```

**Pros**: Principle of least privilege  
**Cons**: More complex to maintain

---

### Strategy 3: Hierarchical Roles

```sql
-- Create role hierarchy: ROLE_ADMIN > ROLE_MANAGER > ROLE_USER

-- ROLE_USER (base role)
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_USER'
  AND s.name IN ('profile:read', 'profile:write');

-- ROLE_MANAGER (inherits USER + adds management scopes)
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_MANAGER'
  AND s.name IN (
    'profile:read', 'profile:write',        -- User scopes
    'user:read', 'user:write', 'invoice:read'  -- Manager scopes
  );

-- ROLE_ADMIN (inherits MANAGER + adds admin scopes)
INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_ADMIN'
  AND s.name IN (
    'profile:read', 'profile:write',        -- User scopes
    'user:read', 'user:write', 'invoice:read',  -- Manager scopes
    'user:manage', 'system:config', 'audit:read'  -- Admin scopes
  );
```

**Pros**: Clear hierarchy, easy to understand  
**Cons**: Role explosion if over-engineered

---

## Database Migration Patterns

### Pattern 1: Additive Migration (Preferred)

Add new scopes/roles without removing existing ones:

```sql
-- V9__add_payment_scopes.sql
INSERT INTO scopes (id, name, description, created_at)
VALUES (UUID(), 'payment:process', 'Process payments', NOW());

INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_ADMIN'
  AND s.name = 'payment:process';
```

**Safe for production**: No data loss

---

### Pattern 2: Replacement Migration (Use with Caution)

Replace deprecated scopes with new ones:

```sql
-- V10__replace_old_user_scopes.sql

-- Add new granular scopes
INSERT INTO scopes (id, name, description, created_at)
VALUES
    (UUID(), 'user:create', 'Create users', NOW()),
    (UUID(), 'user:update', 'Update users', NOW());

-- Migrate role assignments from old "user:write" to new scopes
INSERT INTO role_scopes (role_id, scope_id)
SELECT rs.role_id, s.id
FROM role_scopes rs
JOIN scopes old_scope ON rs.scope_id = old_scope.id
CROSS JOIN scopes s
WHERE old_scope.name = 'user:write'
  AND s.name IN ('user:create', 'user:update');

-- Mark old scope as deprecated (don't delete yet!)
UPDATE scopes
SET description = '[DEPRECATED] Use user:create and user:update instead'
WHERE name = 'user:write';
```

**Rollback plan**: Keep old scope for 30 days before deletion

---

### Pattern 3: Rename Migration

Rename scope while preserving assignments:

```sql
-- V11__rename_profile_scopes.sql

-- Create new scope
INSERT INTO scopes (id, name, description, created_at)
VALUES (UUID(), 'profile:manage', 'Full profile management', NOW());

-- Copy assignments from old scope
INSERT INTO role_scopes (role_id, scope_id)
SELECT rs.role_id, new_scope.id
FROM role_scopes rs
JOIN scopes old_scope ON rs.scope_id = old_scope.id
CROSS JOIN scopes new_scope
WHERE old_scope.name = 'profile:admin'
  AND new_scope.name = 'profile:manage';

-- Delete old assignments
DELETE FROM role_scopes
WHERE scope_id = (SELECT id FROM scopes WHERE name = 'profile:admin');

-- Delete old scope
DELETE FROM scopes WHERE name = 'profile:admin';
```

---

## Rollback & Deprecation

### Deprecation Checklist

Before removing a scope:

1. **Mark as deprecated** (update `description` column)
2. **Log usage** (audit logs to see who's using it)
3. **Notify users** (changelog, email)
4. **Wait 30+ days**
5. **Create rollback migration**
6. **Remove in new migration**

---

### Deprecation Migration

```sql
-- V12__deprecate_old_scopes.sql

-- Mark scope as deprecated
UPDATE scopes
SET description = CONCAT('[DEPRECATED - Remove after 2025-02-01] ', description)
WHERE name = 'user:admin';

-- Log deprecation
INSERT INTO audit_logs (event_type, message, created_at)
VALUES ('SCOPE_DEPRECATED', 'Scope user:admin deprecated. Use user:manage instead.', NOW());
```

---

### Removal Migration (After Deprecation Period)

```sql
-- V13__remove_deprecated_scopes.sql

-- Remove role assignments
DELETE FROM role_scopes
WHERE scope_id IN (
    SELECT id FROM scopes WHERE name = 'user:admin'
);

-- Remove scope
DELETE FROM scopes WHERE name = 'user:admin';

-- Log removal
INSERT INTO audit_logs (event_type, message, created_at)
VALUES ('SCOPE_REMOVED', 'Scope user:admin permanently removed.', NOW());
```

---

### Rollback Migration

```sql
-- V14__rollback_scope_removal.sql

-- Re-create scope
INSERT INTO scopes (id, name, description, created_at)
VALUES (UUID(), 'user:admin', 'Admin user management (restored)', NOW());

-- Restore assignments (requires backup data!)
-- Restore from backup or manually reassign
```

---

## Real-World Examples

### Example 1: E-Commerce Platform

```sql
-- Add product management scopes
INSERT INTO scopes (id, name, description, created_at)
VALUES
    (UUID(), 'product:read', 'View products', NOW()),
    (UUID(), 'product:write', 'Create/update products', NOW()),
    (UUID(), 'product:delete', 'Delete products', NOW()),
    (UUID(), 'product:publish', 'Publish products to storefront', NOW());

-- Add order management scopes
INSERT INTO scopes (id, name, description, created_at)
VALUES
    (UUID(), 'order:read', 'View orders', NOW()),
    (UUID(), 'order:write', 'Create/update orders', NOW()),
    (UUID(), 'order:cancel', 'Cancel orders', NOW()),
    (UUID(), 'order:refund', 'Process refunds', NOW());

-- Create ROLE_PRODUCT_MANAGER
INSERT INTO roles (id, name, description, created_at)
VALUES (UUID(), 'ROLE_PRODUCT_MANAGER', 'Product Catalog Manager', NOW());

INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_PRODUCT_MANAGER'
  AND s.name IN ('product:read', 'product:write', 'product:publish');

-- Create ROLE_ORDER_MANAGER
INSERT INTO roles (id, name, description, created_at)
VALUES (UUID(), 'ROLE_ORDER_MANAGER', 'Order Fulfillment Manager', NOW());

INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_ORDER_MANAGER'
  AND s.name IN ('order:read', 'order:write', 'order:cancel', 'order:refund');
```

---

### Example 2: Healthcare System (HIPAA Compliant)

```sql
-- Add patient data scopes
INSERT INTO scopes (id, name, description, created_at)
VALUES
    (UUID(), 'patient:read', 'View patient demographics', NOW()),
    (UUID(), 'patient:write', 'Create/update patient records', NOW()),
    (UUID(), 'patient:phi-access', 'Access Protected Health Information', NOW()),
    (UUID(), 'patient:export', 'Export patient data', NOW());

-- Add prescription scopes
INSERT INTO scopes (id, name, description, created_at)
VALUES
    (UUID(), 'prescription:read', 'View prescriptions', NOW()),
    (UUID(), 'prescription:write', 'Create prescriptions', NOW()),
    (UUID(), 'prescription:approve', 'Approve prescription orders', NOW());

-- Create ROLE_DOCTOR
INSERT INTO roles (id, name, description, created_at)
VALUES (UUID(), 'ROLE_DOCTOR', 'Licensed Physician', NOW());

INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_DOCTOR'
  AND s.name IN (
    'patient:read',
    'patient:write',
    'patient:phi-access',
    'prescription:read',
    'prescription:write',
    'prescription:approve'
  );

-- Create ROLE_NURSE
INSERT INTO roles (id, name, description, created_at)
VALUES (UUID(), 'ROLE_NURSE', 'Registered Nurse', NOW());

INSERT INTO role_scopes (role_id, scope_id)
SELECT r.id, s.id
FROM roles r
CROSS JOIN scopes s
WHERE r.name = 'ROLE_NURSE'
  AND s.name IN (
    'patient:read',
    'patient:write',
    'prescription:read'
  );
```

---

## Quick Reference Commands

### View Current Scopes

```sql
SELECT name, description FROM scopes ORDER BY name;
```

### View Current Roles

```sql
SELECT name, description FROM roles ORDER BY name;
```

### View Role→Scope Mapping

```sql
SELECT r.name AS role, s.name AS scope
FROM roles r
JOIN role_scopes rs ON r.id = rs.role_id
JOIN scopes s ON rs.scope_id = s.id
ORDER BY r.name, s.name;
```

### Find Users with Specific Scope

```sql
SELECT u.username, s.name AS scope
FROM users u
JOIN user_roles ur ON u.id = ur.user_id
JOIN roles r ON ur.role_id = r.id
JOIN role_scopes rs ON r.id = rs.role_id
JOIN scopes s ON rs.scope_id = s.id
WHERE s.name = 'invoice:approve'
ORDER BY u.username;
```

---

## Checklist for Extensions

Before deploying changes:

- [ ] **Migration created** (Flyway SQL file)
- [ ] **Migration tested** (dev environment)
- [ ] **Domain model updated** (if using constants)
- [ ] **Endpoints protected** (@PreAuthorize annotations)
- [ ] **Tests written** (authorization tests)
- [ ] **Documentation updated** (RBAC matrix, OpenAPI)
- [ ] **Changelog updated** (version notes)
- [ ] **Team notified** (Slack, email)
- [ ] **Rollback plan prepared**

---

## References

- [RBAC+ABAC Matrix](rbac-abac-matrix.md)
- [Scope Design Strategy](scope-design-strategy.md)
- [Scope Implementation Guide](scope-implementation-guide.md)
- [Flyway Documentation](https://flywaydb.org/documentation/)

---

**Last Updated**: 2025-12-26  
**Maintainer**: Security Team
