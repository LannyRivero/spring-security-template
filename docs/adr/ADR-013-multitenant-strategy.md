# ADR-013 — Estrategia Multi-Tenant basada en claims

**Estado:** Aceptado  
**Fecha:** 2025-03-01

## 📌 Contexto
Muchos sistemas requieren separar usuarios por:

- Empresa  
- Organización  
- Cliente  
- Entorno operativo  

Esto debe estar reflejado en los JWT.

## 🏆 Decisión
Incluir un claim estándar:

