# 📚 Documentacion General — Spring Security Template

Este directorio contiene toda la documentacion tecnica, arquitectonica y operativa del proyecto **Spring Security Template**, una plantilla empresarial basada en Spring Boot 3.4.x y Nimbus JOSE + JWT.

Toda la documentacion se estructura de forma modular siguiendo estandares corporativos (C4, ADR, Security Specs, DevOps, QA, etc).

---

## 📘 Indice General

### 1️⃣ Architecture Decision Records (ADR)
Decisiones arquitectonicas documentadas con contexto, alternativas y consecuencias.

📂 [`adr/`](./adr)

---

### 2️⃣ Diagramas de Arquitectura
Diagramas C4, flujos JWT, orden de filtros, arquitectura hexagonal, etc.

📂 [`diagrams/`](./diagrams)

---

### 3️⃣ Seguridad
Documentacion del sistema de seguridad:

- JWT (Access + Refresh)
- Matriz de roles y scopes
- Politicas de acceso (@PreAuthorize)
- Filtros
- Handlers
- Validacion de claves

📂 [`security/`](./security)

---

### 4️⃣ Guias de Integracion
Guias practicas para usar este template en otros proyectos:

- Integracion en microservicios
- Carga de claves RSA
- Como activar HMAC
- Como configurar Refresh Token Rotation
- Uso de TestSecurityConfig

📂 [`guides/`](./guides)

---

### 5️⃣ Testing & QA
Metodologias y patrones de testing:

- Unit Tests
- SecurityConfig Tests
- Filter Tests
- Slice Tests (@WebMvcTest)
- Integracion (Testcontainers)
- Reglas de cobertura

📂 [`testing/`](./testing)

---

### 6️⃣ DevOps / CI-CD
Documentacion para despliegues, pipelines y configuraciones de entorno:

- GitHub Actions
- Dockerfile seguro
- Perfiles dev/test/prod
- Kubernetes Ready
- Liveness/Readiness

📂 [`devops/`](./devops)

---

### 7️⃣ Extensiones Futuras
Documentos de roadmap tecnico:

- OAuth2 Authorization Server
- JWE encryption
- Multi-tenant avanzado
- Impersonacion
- Token introspection

📂 [`future/`](./future)

---

## 🎯 Objetivo del directorio

Permitir a cualquier desarrollador (actual o futuro) comprender:

- El por que de las decisiones tomadas  
- Como funciona la seguridad del proyecto  
- Como extenderlo de forma correcta  
- Como integrarlo en un entorno corporativo  

---

Si tienes dudas sobre algun apartado, revisa los ADR correspondientes o contacta con arquitectura.

