# 📊 Diagramas de Arquitectura — Spring Security Template

Este directorio contiene todos los diagramas del sistema, incluyendo:

---

## 📌 Diagramas C4

### 1. Diagrama de Contexto (C4-1)
Muestra los actores externos y su relación con el sistema.

### 2. Diagrama de Contenedores (C4-2)
Representa componentes principales: Web, Application, Domain, Infrastructure.

### 3. Diagrama de Componentes (C4-3)
Detalla módulos internos: filtros, providers, adaptadores, casos de uso.

---

## 🔐 Flujos de Seguridad

### - Flujo Login (Credentials → JWT)
### - Flujo Refresh Token
### - Flujo Me (usuario autenticado)
### - Flujo de Revocación

---

## 🛡 Orden de Filtros (Security Filters Chain)

Incluye:

- CorrelationIdFilter
- SecurityHeadersFilter
- LoginRateLimitingFilter
- JwtAuthorizationFilter
- AuthEntryPoint y AccessDenied

---

## 🧩 Arquitectura Hexagonal

Representación visual del diseño ports & adapters.

---

Todos se entregan en:

- `.drawio` → editable  
- `.png` → para documentación  

---
