# 🧠 Architecture Decision Records (ADR) — Indice

Este directorio contiene todas las **decisiones arquitectonicas** relevantes relacionadas con el Spring Security Template.

Cada ADR documenta:

- Contexto  
- Decision  
- Alternativas consideradas  
- Justificacion  
- Consecuencias  

Los ADRs NO se eliminan: se crean nuevos si una decision se revoca o actualiza.

---

## 📑 Lista de ADRs

### 🔐 Seguridad y Autenticacion

| Nº | Tema | Enlace |
|----|------|--------|
| ADR-001 | Firma JWT: RSA vs HMAC | [ADR-001-rsa-vs-hmac.md](ADR-001-rsa-vs-hmac.md) |
| ADR-003 | Refresh Token Rotation | [ADR-003-refresh-token-rotation.md](ADR-003-refresh-token-rotation.md) |
| ADR-004 | Blacklisting | [ADR-004-blacklisting-strategy.md](ADR-004-blacklisting-strategy.md) |
| ADR-005 | Nimbus JOSE + JWT | [ADR-005-nimbus-vs-jjwt.md](ADR-005-nimbus-vs-jjwt.md) |
| ADR-008 | Fuentes de claves RSA | [ADR-008-rsa-key-sources.md](ADR-008-rsa-key-sources.md) |
| ADR-011 | JWE Encryption | [ADR-011-jwe-support.md](ADR-011-jwe-support.md) |
| ADR-017 | Sliding Sessions | [ADR-017-sliding-sessions.md](ADR-017-sliding-sessions.md) |

---

### 🧩 Arquitectura y diseño

| Nº | Tema | Enlace |
|----|------|--------|
| ADR-002 | Arquitectura Hexagonal | [ADR-002-hexagonal-architecture.md](ADR-002-hexagonal-architecture.md) |
| ADR-006 | RBAC + Scope Policy | [ADR-006-rbac-scope-policy.md](ADR-006-rbac-scope-policy.md) |
| ADR-007 | Filtros personalizados | [ADR-007-custom-filters.md](ADR-007-custom-filters.md) |
| ADR-013 | Multi-Tenant | [ADR-013-multitenant-strategy.md](ADR-013-multitenant-strategy.md) |

---

### 🔧 Configuracion y Entornos

| Nº | Tema | Enlace |
|----|------|--------|
| ADR-009 | InMemory Providers en dev | [ADR-009-inmemory-providers-dev.md](ADR-009-inmemory-providers-dev.md) |
| ADR-010 | Observabilidad con Prometheus | [ADR-010-observability-prometheus.md](ADR-010-observability-prometheus.md) |
| ADR-016 | Rotacion de claves RSA | [ADR-016-rsa-key-rotation.md](ADR-016-rsa-key-rotation.md) |
| ADR-014 | Auditoria de seguridad | [ADR-014-security-audit.md](ADR-014-security-audit.md) |

---

### 🌐 Integraciones

| Nº | Tema | Enlace |
|----|------|--------|
| ADR-012 | Integracion con OAuth2 Authorization Server | [ADR-012-oauth2-integration.md](ADR-012-oauth2-integration.md) |
| ADR-015 | Impersonacion | [ADR-015-impersonation.md](ADR-015-impersonation.md) |

---

## ✔ Buenas practicas de ADR

- Un ADR = una decision  
- Nunca borrar ADR antiguos  
- Un ADR puede “rechazar” o “reemplazar” otro  
- Deben ser breves y claros  
- Deben permitir a cualquier dev entender por que las cosas son como son

---

Fin del indice. Ahora revisa cada ADR para comprender decisiones especificas del sistema.

