# 🔐 Autorización (RBAC + Scopes)

La plantilla combina:

✔ RBAC — Role-Based Access Control  
✔ ABAC (light) — Scopes / permisos finos

---

## 🧩 Roles disponibles

| Rol        | Descripción                 |
| ---------- | --------------------------- |
| ROLE_ADMIN | Acceso total                |
| ROLE_USER  | Acceso limitado             |
| ROLE_DEV   | Rol especial para desarrollo |

---

## 🧩 Scopes disponibles

| Scope           | Descripción               |
|-----------------|---------------------------|
| `profile:read`  | Leer info del usuario     |
| `*`             | Acceso completo (admin)   |

---

## 🎯 Cómo se aplican

Los roles otorgan un conjunto de scopes.

Ejemplo:

ROLE_ADMIN → *
ROLE_USER → profile:read


---

## ⚙ Autorización en Spring

### Anotación

```java
@PreAuthorize("hasAuthority('profile:read')")

O validación vía scopes

@PreAuthorize("hasAuthority('admin') or hasAuthority('*')")

🔒 SecurityConfig

La autorización final se aplica en:

JwtAuthorizationFilter

SecurityConfig vía DSL