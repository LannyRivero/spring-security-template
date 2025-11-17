# 📚 Documentación General — Spring Security Template

Este directorio contiene toda la documentación técnica, arquitectónica y operativa del proyecto **Spring Security Template**, una plantilla empresarial basada en Spring Boot 3.4.x y Nimbus JOSE + JWT.

Toda la documentación se organiza siguiendo estándares corporativos utilizados en entornos de alta seguridad.

---

## 📘 Índice de Documentación

### 1️⃣ Architecture Decision Records (ADR)
Decisiones arquitectónicas documentadas con contexto, alternativas y consecuencias.

📂 [`adr/`](./adr)

---

### 2️⃣ Diagramas de Arquitectura
Diagramas C4 (context, container, component), flujos de seguridad, orden de filtros y arquitectura hexagonal.

📂 [`diagrams/`](./diagrams)

---

### 3️⃣ Seguridad
Documentación detallada sobre:

- Flujos JWT (Login, Refresh, Me)
- Especificación de tokens (claims, expiración)
- Matriz de Roles/Scopes
- Orden de filtros
- Políticas de acceso (@PreAuthorize)

📂 [`security/`](./security)

---

### 4️⃣ Guías de Configuración
Guías prácticas para usar esta plantilla en otros proyectos:

- Cómo integrar el template en microservicios
- Cómo cargar claves RSA
- Cómo activar HMAC
- Cómo trabajar con Refresh Token Rotation
- Cómo usar TestSecurityConfig

📂 [`guides/`](./guides)

---

### 5️⃣ Testing y QA
Guías y buenas prácticas de testing:

- Unit tests
- Testing de Nimbus
- Testing de filtros
- Testing de SecurityConfig
- @WebMvcTest
- Testcontainers
- Reglas de cobertura

📂 [`testing/`](./testing)

---

### 6️⃣ DevOps / CI-CD
Documentación operativa:

- GitHub Actions
- Dockerfile
- Perfiles dev/test/prod
- Pipeline de calidad
- Preparación para Kubernetes

📂 [`devops/`](./devops)

---

### 7️⃣ Futuras Extensiones
Ideas y componentes planificados:

- OAuth2 Authorization Server
- JWE encryption
- Multi-tenant avanzado
- Impersonación
- Token introspection endpoint

📂 [`future/`](./future)

---

## ✨ Objetivo

Crear una documentación clara, útil y mantenible, que permita a cualquier desarrollador:

- Comprender las decisiones arquitectónicas
- Integrar fácilmente el módulo de seguridad
- Extenderlo sin romper su diseño
- Mantener un sistema de seguridad empresarial

---
