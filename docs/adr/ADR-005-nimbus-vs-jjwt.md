# ADR-005 — Uso de Nimbus JOSE + JWT
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado

---

## 🎯 Contexto

El sistema necesita generar y validar JWT con:

- Claims avanzados
- RSA/HMAC intercambiable
- Control criptográfico granular
- Soporte corporativo (JOSE, JWK, JWE)
- Testing completo sin acoplar la lógica

JJWT, aunque popular, es limitado:

- No soporta JOSE completo  
- Integración pobre con OAuth2  
- No soporta JWE  
- Extensibilidad reducida  

---

## 🧠 Decisión

Se adopta **Nimbus JOSE + JWT** como biblioteca principal.

---

## ✔ Razones principales

### 1. Estándar corporativo
Usado por:

- Google
- Auth0
- Okta
- AWS Cognito
- Azure AD

### 2. JOSE completo
Permite:

- JWS: firma
- JWE: cifrado
- JWK: claves
- Rotación de claves
- Thumbprints

### 3. Control total del JWT
- Claims personalizados
- Custom header parameters
- Verify/Sign flexible

### 4. Facilita integraciones futuras
- Authorization Server
- Resource Server
- JWKS endpoint

### 5. Tests más fiables
- Validación criptográfica completa
- Soporte para claves en memoria

---

## 🧩 Alternativas consideradas

### 1. JJWT  
✗ Sin soporte JOSE  
✗ Sin JWE  
✗ Poco usado en proyectos enterprise  

### 2. Keycloak Adapter  
✗ Overkill  
✗ Requiere Keycloak como dependencia  

---

## 📌 Consecuencias

### Positivas
- Seguridad enterprise real  
- Flexible y extensible  
- Preparado para OAuth2/OIDC  
- Estándar moderno para microservicios  

### Negativas
- Más complejo para principiantes  
- Requiere más configuraciones  

---

## 📤 Resultado

Se adopta Nimbus JOSE + JWT para:

- TokenProvider
- Validación criptográfica
- Carga de claves RSA/HMAC
- Tests completos

