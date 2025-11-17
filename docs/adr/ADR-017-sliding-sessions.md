# ADR-017 — Sliding Sessions (expiración compuesta Access + Refresh)

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## 📌 Contexto
Los usuarios requieren sesiones largas, pero seguras.  
Las empresas usan:

- Access Token corto (5–15 min)
- Refresh Token largo (7–30 días)
- Sliding expiration → mientras el usuario esté activo, la sesión se extiende

## 🏆 Decisión
Implementar Sliding Sessions:

- El Refresh Token se renueva si:
  - No está cerca de expirar
  - No ha sido revocado
  - El usuario sigue activo

## 🎯 Motivaciones
- Mejor UX  
- Evita expiraciones abruptas  
- Evita sesiones abandonadas eternamente  

## 🔄 Alternativas consideradas
- ❌ Access Tokens largos → inseguros  
- ❌ Refresh token estático → UX pobre

## 📌 Consecuencias
- Requiere control de tiempo de actividad  
- Incrementa auditoría  
- Aumenta seguridad y usabilidad
