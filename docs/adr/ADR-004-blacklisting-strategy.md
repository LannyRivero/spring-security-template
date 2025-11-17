# ADR-004 — Estrategia de Blacklisting
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

El sistema debe permitir:

- Invalidar tokens comprometidos
- Revocar sesiones al instante
- Soportar Refresh Token Rotation
- Cumplir requisitos de banca/empresa:
  - Logout real
  - Revocación administrativa
  - Detección de replay attacks

Dado que los JWT son *stateless*, su invalidación requiere un mecanismo explícito.

---

## 🧠 Decisión

Se implementa un **Blacklisting por jti** (ID del token) como mecanismo oficial.

- Cada JWT incluye un `jti` único.
- Al invalidar un token → se almacena temporalmente su `jti`.
- Los filtros verifican si el `jti` está invalidado.

En dev/test se usa **InMemoryTokenBlacklistGateway**.  
En producción puede usarse Redis/Vault.

---

## ✔ Razones principales

### 1. Es compatible con JWT y sin estado
No requiere sesiones completas en BD.

### 2. Permite logout real
El token queda inutilizado antes del expiry.

### 3. Es requerido por:
- OWASP ASVS  
- Lineamientos PCI-DSS  
- OIDC Session Security

### 4. Escalable con Redis
TTL automático = exp del token.

---

## 🧩 Alternativas consideradas

### 1. No usar blacklist  
✗ No hay logout  
✗ No se puede bloquear un token robado  
✗ No detecta refresh replay  

### 2. Sessions tradicionales  
✗ Rompe la idea de JWT stateless  
✗ Mucho overhead  

### 3. Revocar claves RSA  
✗ Rompería todas las sesiones  
✗ No es viable en microservicios  

---

## 📌 Consecuencias

### Positivas
- Logout real  
- Protección ante robo de tokens  
- Apoyo al refresh rotation  
- Fácil de extender a Redis  

### Negativas
- Añade complejidad en prod  
- Requiere almacenamiento temporal  

---

## 📤 Resultado

- Implementación en dev: in-memory  
- Diseño preparado para:
  - Redis
  - Hazelcast
  - DynamoDB TTL  
- Validación en JwtAuthorizationFilter

