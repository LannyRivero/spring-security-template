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

"tenant": "<ID del tenant>"

Y un módulo `TenantPolicy` para validar accesos por tenant.

## 🎯 Motivaciones
- Soporte nativo a multicliente  
- Integración sencilla con API Gateway  
- Fácil extensión a roles/permissions específicos por tenant

## 🔄 Alternativas consideradas
- ❌ Multi-tenant por base de datos → demasiado rígido para un template  
- ❌ Multi-tenant por cabecera HTTP → manipulable

## 📌 Consecuencias
- Cada request deberá validar el tenant  
- Los tokens requerirán un claim adicional  
- Permite migrar fácilmente a sistemas multi-tenant avanzados
