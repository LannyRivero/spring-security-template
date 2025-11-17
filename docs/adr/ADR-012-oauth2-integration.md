# ADR-012 — Interoperabilidad futura con OAuth2 / OpenID Connect
📅 Fecha: 2025-11-17  
📁 Estado: Planificado

---

## 🎯 Contexto

Aunque el proyecto usa autenticación "propietaria" basada en:

- JWT autocontenidos  
- Roles  
- Scopes  
- Refresh tokens  

muchos ecosistemas corporativos usan:

- Identity Providers (IdP)
- Keycloak
- Auth0
- Azure AD
- Okta

Por lo tanto, la plantilla debe ser compatible en un futuro con OAuth2/OIDC.

---

## 🧠 Decisión

No implementar OAuth2/OIDC actualmente, pero preparar:

- `TokenProvider` como interfaz desacoplada  
- Scopes compatibles con OIDC (`resource:action`)  
- Claims estándar (sub, iss, exp)  
- Nimbus (compatible con JWKS)  
- Arquitectura hexagonal lista para un `ExternalIdpAdapter`

---

## ✔ Razones principales

### 1. Evitar sobrecarga inicial  
OAuth2 añade:

- Authorization Server  
- Discovery  
- Introspection  
- Refresh endpoint complejo  

### 2. Mantener simplicidad  
Esta plantilla debe ser usable *sin* un IdP externo.

### 3. Preparación para escenarios enterprise  
Poder sustituir el login local por Keycloak implica 0 cambios en:

- domain  
- application  
- controllers  

Solo sustituir el adaptador.

---

## 🧩 Alternativas consideradas

### Implementar OAuth2/OIDC desde el principio  
✗ Rompe simplicidad  
✗ Exige demasiada configuración  
✗ No aplicable en todos los casos  

---

## 📌 Consecuencias

### Positivas
- Evolución futura 100% posible  
- Arquitectura preparada  
- Integración con Keycloak trivial  

### Negativas
- Capacidad limitada en escenarios federados  
- No hay SSO aún  

---

## 📤 Resultado

La plantilla queda preparada para un futuro módulo OAuth2/OIDC sin necesidad de reescribir el sistema.

