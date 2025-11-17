# ADR-003 — Refresh Token Rotation
📅 Fecha: 2025-11-17  
📁 Estado: Aprobado  

---

## 🎯 Contexto

Los Refresh Tokens son especialmente sensibles porque:

- Tienen mayor duración
- Permiten generar nuevos Access Tokens
- Su compromiso equivale a secuestrar la sesión completa

El sistema debe:

1. Evitar reutilización del Refresh Token  
2. Detectar robo de tokens  
3. Mantener sesiones seguras en producción  

---

## 🧠 Decisión

El template adopta **Refresh Token Rotation**:

- Cada vez que se usa un refresh token → se emite uno nuevo  
- El token viejo se invalida inmediatamente  
- Se registra el `jti` o fingerprint  

---

## ✔ Razones principales

### 1. Mejora crítica en seguridad
Evita ataques donde:

- Alguien roba un refresh  
- Lo usa después de que el usuario ya pidió otro  

Esto queda automáticamente bloqueado.

### 2. Estándar en OIDC y bancos
Google, Auth0, Okta, AWS Cognito…  
todos implementan rotating refresh.

### 3. Permite detección de replay attacks
Si llega un refresh token **ya rotado**, es señal de intrusión.

---

## 🧩 Alternativas consideradas

### 1. Refresh Tokens fijos  
✗ Poco seguro  
✗ No detecta robo  
✗ No recomendado en 2025

### 2. Sessions (stateful)  
✗ Requiere base de datos  
✗ No compatible con JWT stateless

---

## 📌 Consecuencias

### Positivas
- Sesiones más seguras  
- Detección de ataques  
- Compatible con JWKS / OAuth2  

### Negativas
- Requiere blacklisting de refresh tokens antiguos  
- Añade complejidad en dev  

---

## 📤 Resultado

- Refresh tokens llevan `jti` único  
- Se invalidan en cada uso  
- El sistema está preparado para:  
  - Persistencia de jti por usuario  
  - Blacklist  
  - Auditoría  


