# ADR-014 — Auditoría de Seguridad basada en eventos

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## 📌 Contexto
Las auditorías son obligatorias en sistemas corporativos:

- Login / Logout  
- Intentos fallidos  
- Tokens generados  
- Tokens revocados  
- Usuarios bloqueados  

## 🏆 Decisión
Crear un servicio centralizado:

### SecurityAuditService

Que genere eventos estándares:

- LOGIN_SUCCESS  
- LOGIN_FAILURE  
- TOKEN_REVOKED  
- USER_LOCKED  
- USER_DISABLED  

Y que pueda integrarse con:

- ELK  
- OpenSearch  
- Loki  
- Grafana

## 🎯 Motivaciones
- Cumplimiento normativo  
- Detección rápida de ataques  
- Trazabilidad total  

## 🔄 Alternativas consideradas
- ❌ Logging disperso → difícil de rastrear  
- ❌ Auditoría en DB siempre → poco flexible

## 📌 Consecuencias
- Aumenta observabilidad  
- Permite análisis de seguridad en tiempo real
