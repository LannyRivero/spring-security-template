# ADR-001 — Algoritimo de firma JWT: RSA vs HMAC
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado  
🔄 Reemplaza a: Ninguno

---

## 🎯 Contexto

El sistema requiere firmar y validar JWT para autenticación y autorización.  
Existen dos opciones principales:

- **HMAC (HS256/384/512)**: clave simétrica compartida.
- **RSA (RS256/384/512)**: clave privada para firmar, clave pública para validar.

El proyecto debe ser compatible con entornos:

- Desarrollo local  
- Testing automatizado  
- Producción corporativa (KMS, keystores, Vault)  

Además, la plantilla debe ser reutilizable por otros microservicios.

---

## 🧠 Decisión

Se adopta **RSA como algoritmo por defecto**.  
Se mantiene **HMAC disponible como fallback opcional**.

---

## ✔ Razones principales

### Por qué **RSA** es el estándar:
- Separación clara entre **firma** (servidor) y **validación** (otros servicios)
- No expone la clave privada en microservicios
- Compatible con:
  - OAuth2
  - OIDC
  - Kubernetes Secrets
  - AWS KMS / Azure KeyVault
- Facilita la rotación de claves
- Escalable para arquitecturas distribuidas

### Por qué **HMAC** no es adecuado para producción:
- Una única clave compartida
- Riesgo: si un servicio filtra la clave, todos quedan comprometidos
- Rotación más compleja
- No compatible con validación cruzada multi-servicio

---

## 🧩 Alternativas consideradas

### 1. Solo HMAC  
**Descartada.**  
✓ Simple  
✗ Riesgo de seguridad elevado  
✗ Limitado para arquitecturas distribuidas  
✗ No corporativo  

### 2. Solo RSA  
**Posible pero no flexible.**  
Se requiere HMAC en dev para trabajar sin claves.

### 3. EC (Elliptic Curve)  
**Descartada por ahora:**  
Aunque ES256 es más moderno, RSA sigue siendo estándar en empresas.

---

## 📌 Consecuencias

### Positivas
- Seguridad corporate-grade
- Validación JWT distribuida entre microservicios
- Integración con Vault/KMS
- Escalabilidad sin exponer claves privadas

### Negativas
- Configuración más compleja en dev
- Requiere gestión de claves (keystore, vault, etc.)

---

## 📤 Resultado

El template soporta:

- ✔ **RSA como default (prod/test/dev)**
- ✔ **HMAC como fallback**
- ✔ Carga de claves desde:  
  - classpath  
  - filesystem  
  - keystore/JKS  
  - AWS KMS / GCP Secrets / Azure  


