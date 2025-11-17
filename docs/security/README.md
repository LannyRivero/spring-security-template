# 🔐 Documentación de Seguridad — Spring Security Template

Este directorio contiene toda la documentación relacionada con:

- Autenticación
- Autorización
- JWT
- Scopes y roles
- Filtros
- Handlers
- Configuración de claves

---

## 📘 Contenido

### 1️⃣ Especificación JWT
📄 `jwt-spec.md`  
Define:

- Access Token
- Refresh Token
- Claims
- Tiempo de vida
- Ejemplos codificados

---

### 2️⃣ Matriz de Roles/Scopes
📄 `roles-scopes-matrix.md`  
Matriz RBAC + ABAC:

| Rol | Scopes | Descripción |

---

### 3️⃣ Filtros de Seguridad
📄 `filters-overview.md`  
Describe cada filtro:

- JwtAuthorizationFilter  
- SecurityHeadersFilter  
- LoginRateLimitingFilter  
- CorrelationIdFilter  
- AuthNoCacheFilter  

---

### 4️⃣ Políticas de Acceso
📄 `preauthorize-policy.md`  
Documenta el uso de:

```java
@PreAuthorize("hasAuthority('SCOPE_profile:read')")
```
---

### 5️⃣ Manejo de claves (RSA/HMAC)

📄 `keys-management.md`

Incluye:

- Cómo cargar RSA desde classpath

- Cómo usar filesystem

- Cómo usar keystore JKS

- Configuración HMAC