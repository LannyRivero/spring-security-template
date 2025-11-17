# ADR-015 — Hardening de Seguridad (Headers, TLS, JWT)
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

La seguridad moderna exige no solo autenticación, sino un **hardening** transversal:

- Cabeceras anti-XSS  
- HSTS  
- TLS estricto  
- Deshabilitar cache de tokens  
- Validación de claims JWT  
- Logs sin PII  

La aplicación debe cumplir estándares como:

- OWASP ASVS  
- NIST 800-63  
- PCI-DSS (nivel básico)  

---

## 🧠 Decisión

Se definen reglas estrictas:

---

### 1️⃣ Cabeceras de Seguridad (SecurityHeadersFilter)

Incluye:

- `Strict-Transport-Security`  
- `X-Content-Type-Options: nosniff`  
- `X-Frame-Options: DENY`  
- `X-XSS-Protection: 1; mode=block`  
- `Referrer-Policy: no-referrer`  
- `Permissions-Policy` adecuada  

---

### 2️⃣ TLS obligatorio en producción

- HTTPS solo  
- No permitir downgrade a HTTP  
- TLS 1.3 preferido  

---

### 3️⃣ Validación estricta de JWT

- `iss` comprobado  
- `exp` obligatorio  
- `iat` obligatorio  
- `jti` generado  
- Scopes validados en aplicación  

---

### 4️⃣ Logs sin información sensible

Prohibido loguear:

- tokens  
- contraseñas  
- headers Authorization  
- keys  

Además, usar `Correlation-ID` para trazabilidad.

---

## ✔ Razones principales

### 1. Seguridad moderna real  
Hardening = varios niveles de defensa.

### 2. Compliant con regulaciones  
Cumple ASVS, PCI, NIST.

### 3. Listo para auditorías  
El sistema es auditable.

---

## 🧩 Alternativas consideradas

### 1. Seguridad básica  
✗ Expuesta a ataques clásicos  

### 2. Delegar hardening a nginx/gateway  
✗ Parcial  
✗ La app también debe protegerse internamente  

---

## 📌 Consecuencias

### Positivas
- Seguridad de nivel bancario  
- Compatible con auditorías  
- Reducido ataque de superficie  

### Negativas
- Más filtros y más coste computacional  

---

## 📤 Resultado

El microservicio implementa un hardening moderno, estricto y auditable, manteniendo flexibilidad según entorno (dev/test/prod).


