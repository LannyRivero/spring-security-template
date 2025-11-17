# ADR-015 — Manejo de sesiones impersonadas para administradores

**Estado:** Planeado  
**Fecha:** 2025-03-01

## 📌 Contexto
Administradores y equipos de soporte necesitan ver el sistema como un usuario real para depuración o asistencia.

## 🏆 Decisión
Implementar impersonación mediante claim:

### "act_as": "<id real del usuario>"


Con restricciones:

- Tiempo limitado  
- Registro en auditoría  
- Permisos elevados requeridos  
- Prohibido impersonar a otros administradores

## 🎯 Motivaciones
- Mejora soporte técnico  
- Facilita depuración de permisos  
- Estándar en plataformas SaaS

## 🔄 Alternativas consideradas
- ❌ Acceder como el usuario real → inseguro  
- ❌ Acceso root siempre → demasiado riesgoso

## 📌 Consecuencias
- El sistema debe diferenciar “actor” vs “usuario final”  
- Las auditorías deben registrar ambas identidades

