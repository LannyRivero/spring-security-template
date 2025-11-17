# ADR-006 — Modelo RBAC + Scope Policy (ABAC)
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

El sistema debe permitir un modelo de autorización:

- Simple de entender (roles)
- Extensible y granular (scopes)
- Independiente del framework (Web, Kafka, gRPC)
- Fácil de adaptar a otros microservicios

Se necesitan permisos finos sin perder la simplicidad del RBAC.

---

## 🧠 Decisión

Se adopta un **modelo híbrido RBAC + ABAC basado en scopes**:

- Roles definen accesos principales  
- Scopes definen permisos finos por recurso  
- ScopePolicy decide si un usuario puede realizar una acción  

---

## ✔ Razones principales

### 1. RBAC es simple y estándar  
- Role: ADMIN, USER, DEV  
- Fácil para empresas y equipos  

### 2. ABAC vía Scopes es flexible  
Permite:  
- `profile:read`  
- `users:delete`  
- `technologies:update`  

### 3. Se integra perfectamente con:
- JWT claims  
- @PreAuthorize  
- SecurityExpressionHandler personalizado  

### 4. No acopla permisos a la base de datos
Permite microservicios sin tablas de permisos.

---

## 🧩 Alternativas consideradas

### 1. Solo RBAC  
✗ Permisos demasiado amplios  
✗ No apto para sistemas grandes  

### 2. Permisos en base de datos  
✗ Complejo  
✗ Dificulta despliegue  
✗ No necesario para el template  

---

## 📌 Consecuencias

### Positivas
- Permisos finos sin complejidad excesiva  
- Roles simples para empresas  
- Scopes listos para OAuth2/OIDC  
- Fácil de integrar y testear  

### Negativas
- Debe mantenerse una matriz roles/scopes  
- ScopePolicy requiere mantenimiento  

---

## 📤 Resultado

El template incluye:

- Claim `roles`: RBAC  
- Claim `scopes`: ABAC  
- ScopePolicy configurable  
- Fácil integración con `@PreAuthorize("hasScope('x')")`

